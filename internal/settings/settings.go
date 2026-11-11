package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"domain-manager/internal/models"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

var defaults = map[string]string{
	"site_name":                 "Domain Manager",
	"site_url":                  "",
	"timezone":                  "Asia/Shanghai",
	"domain_check_cron":         "0 3 * * *",
	"ssl_check_cron":            "0 */6 * * *",
	"renewal_check_cron":        "0 4 * * *",
	"alert_scan_cron":           "0 * * * *",
	"notification_retry_cron":   "*/10 * * * *",
	"domain_expiry_thresholds":  "[30,15,7,3,1,0]",
	"ssl_expiry_thresholds":     "[30,15,7,3,1]",
	"domain_warning_days":       "30",
	"ssl_warning_days":          "30",
	"acme_email":                "",
	"acme_staging":              "true",
	"acme_key_type":             "rsa2048",
	"acme_renew_days":           "30",
	"acme_http01_mode":          "standalone",
	"acme_http01_iface":         "",
	"acme_http01_port":          "80",
	"acme_webroot":              "./data/acme-webroot",
	"acme_default_dns_provider": "cloudflare",
	"auto_deploy":               "false",
	"deploy_dir":                "./data/deploy",
	"deploy_script":             "",
	"http_timeout_seconds":      "15",
	"max_concurrency":           "5",
	"rdap_timeout_seconds":      "15",
	"whois_enabled":             "true",
	"allow_private_targets":     "false",
	"notification_max_retries":  "5",
	"session_ttl_hours":         "12",
	"login_max_attempts":        "5",
	"login_lock_minutes":        "15",
	"acme_max_attempts":         "3",
	"acme_concurrency":          "2",
	"acme_renew_cooldown_hours": "24",
	"log_retention_days":        "90",
	"public_url":                "",
	"ssl_default_port":          "443",
}

var editable = map[string]bool{
	"site_name": true, "site_url": true, "timezone": true,
	"domain_check_cron": true, "ssl_check_cron": true, "renewal_check_cron": true,
	"alert_scan_cron": true, "notification_retry_cron": true,
	"domain_expiry_thresholds": true, "ssl_expiry_thresholds": true,
	"domain_warning_days": true, "ssl_warning_days": true,
	"acme_email": true, "acme_staging": true, "acme_key_type": true, "acme_renew_days": true,
	"acme_http01_mode": true, "acme_http01_iface": true, "acme_http01_port": true, "acme_webroot": true,
	"acme_default_dns_provider": true, "auto_deploy": true, "deploy_dir": true, "deploy_script": true,
	"http_timeout_seconds": true, "max_concurrency": true, "rdap_timeout_seconds": true,
	"whois_enabled": true, "allow_private_targets": true, "notification_max_retries": true,
	"session_ttl_hours": true, "login_max_attempts": true, "login_lock_minutes": true,
	"acme_max_attempts": true, "acme_concurrency": true, "acme_renew_cooldown_hours": true,
	"log_retention_days": true, "public_url": true, "ssl_default_port": true,
}

type Manager struct {
	db    *gorm.DB
	mu    sync.RWMutex
	cache map[string]string
}

func New(db *gorm.DB) (*Manager, error) {
	m := &Manager{db: db, cache: make(map[string]string)}
	if err := m.Seed(); err != nil {
		return nil, err
	}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Seed() error {
	for k, v := range defaults {
		var count int64
		if err := m.db.Model(&models.SystemSetting{}).Where("key = ?", k).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if err := m.db.Create(&models.SystemSetting{Key: k, Value: v}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) reload() error {
	var rows []models.SystemSetting
	if err := m.db.Find(&rows).Error; err != nil {
		return err
	}
	cache := make(map[string]string, len(defaults))
	for k, v := range defaults {
		cache[k] = v
	}
	for _, row := range rows {
		cache[row.Key] = row.Value
	}
	m.mu.Lock()
	m.cache = cache
	m.mu.Unlock()
	return nil
}

func (m *Manager) Get(key string) string {
	m.mu.RLock()
	v := m.cache[key]
	m.mu.RUnlock()
	return v
}

func (m *Manager) GetDefault(key string) string {
	return defaults[key]
}

func (m *Manager) Int(key string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(m.Get(key)))
	return v
}

func (m *Manager) Bool(key string) bool {
	v, _ := strconv.ParseBool(strings.TrimSpace(m.Get(key)))
	return v
}

// Location returns the configured IANA timezone. Callers should keep the
// returned *time.Location instead of mutating the process-wide time.Local.
func (m *Manager) Location() *time.Location {
	tz := strings.TrimSpace(m.Get("timezone"))
	if tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.Local
}

func (m *Manager) Duration(key string, fallback time.Duration) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(m.Get(key)))
	if err != nil || secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

func (m *Manager) Thresholds(key string) []int {
	var out []int
	if err := json.Unmarshal([]byte(m.Get(key)), &out); err != nil {
		return nil
	}
	return out
}

func (m *Manager) All() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.cache))
	for k, v := range m.cache {
		out[k] = v
	}
	return out
}

func (m *Manager) Update(values map[string]string) error {
	for k, v := range values {
		if !editable[k] {
			return fmt.Errorf("不允许修改配置项 %s", k)
		}
		if err := Validate(k, v); err != nil {
			return err
		}
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		for k, v := range values {
			result := tx.Model(&models.SystemSetting{}).Where("key = ?", k).Update("value", v)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				if err := tx.Create(&models.SystemSetting{Key: k, Value: v}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (m *Manager) Reload() error {
	return m.reload()
}

func Validate(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "domain_check_cron", "ssl_check_cron", "renewal_check_cron", "alert_scan_cron", "notification_retry_cron":
		if _, err := cron.ParseStandard(value); err != nil {
			return fmt.Errorf("Cron 表达式无效: %w", err)
		}
	case "domain_expiry_thresholds", "ssl_expiry_thresholds":
		var vals []int
		if err := json.Unmarshal([]byte(value), &vals); err != nil || len(vals) == 0 {
			return errors.New("告警阈值必须是整数数组")
		}
		for _, v := range vals {
			if v < 0 || v > 3650 {
				return errors.New("告警阈值必须在 0-3650 天之间")
			}
		}
	case "http_timeout_seconds", "rdap_timeout_seconds":
		n, err := strconv.Atoi(value)
		if err != nil || n < 3 || n > 120 {
			return errors.New("超时时间必须在 3-120 秒之间")
		}
	case "max_concurrency":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 50 {
			return errors.New("并发数必须在 1-50 之间")
		}
	case "acme_concurrency":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 10 {
			return errors.New("ACME 订单并发数必须在 1-10 之间")
		}
	case "acme_http01_port", "ssl_default_port":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("端口必须在 1-65535 之间")
		}
	case "acme_http01_mode":
		if value != "standalone" && value != "webroot" {
			return errors.New("HTTP-01 模式必须为 standalone 或 webroot")
		}
	case "acme_key_type":
		if value != "rsa2048" && value != "rsa4096" && value != "ec256" && value != "ec384" {
			return errors.New("不支持的证书密钥类型")
		}
	case "acme_staging", "auto_deploy", "whois_enabled", "allow_private_targets":
		if _, err := strconv.ParseBool(value); err != nil {
			return errors.New("配置必须是布尔值")
		}
	case "login_max_attempts", "login_lock_minutes", "session_ttl_hours", "acme_renew_days", "acme_max_attempts",
		"acme_renew_cooldown_hours", "log_retention_days", "domain_warning_days", "ssl_warning_days", "notification_max_retries":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 10000 {
			return errors.New("配置必须是有效的正整数")
		}
	case "site_url", "public_url":
		if value != "" {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return errors.New("站点 URL 格式无效")
			}
		}
	case "acme_email":
		if value != "" && (!strings.Contains(value, "@") || len(value) > 255) {
			return errors.New("ACME 邮箱格式无效")
		}
	case "timezone":
		if value == "" {
			return errors.New("时区不能为空")
		}
		if _, err := time.LoadLocation(value); err != nil {
			return errors.New("时区无效，请使用 IANA 时区名称，例如 Asia/Shanghai")
		}
	case "acme_default_dns_provider":
		if value != "cloudflare" && value != "dnspod" && value != "alidns" {
			return errors.New("不支持的 DNS Provider")
		}
	case "deploy_script":
		if value != "" && !strings.HasPrefix(value, "/") {
			return errors.New("部署脚本必须使用绝对路径")
		}
	}
	return nil
}

func Defaults() map[string]string {
	out := make(map[string]string, len(defaults))
	for k, v := range defaults {
		out[k] = v
	}
	return out
}
