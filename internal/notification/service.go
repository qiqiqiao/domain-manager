package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

type messageSender interface {
	Send(ctx context.Context, channelType string, cfg ChannelConfig, msg Message) error
}

type Service struct {
	db       *gorm.DB
	settings *settings.Manager
	cipher   *security.Cipher
	sender   messageSender
}

func NewService(db *gorm.DB, st *settings.Manager, c *security.Cipher) *Service {
	return &Service{db: db, settings: st, cipher: c, sender: NewSender(st)}
}

func (s *Service) EncryptConfig(cfg ChannelConfig) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return s.cipher.Encrypt(string(data))
}

func (s *Service) DecryptConfig(raw string) (ChannelConfig, error) {
	plain, err := s.cipher.Decrypt(raw)
	if err != nil {
		return ChannelConfig{}, err
	}
	return ParseConfig(plain)
}

func (s *Service) ValidateChannel(channelType string, cfg ChannelConfig) error {
	return ValidateConfig(channelType, cfg, s.settings.Bool("allow_private_targets"))
}

// MaskedConfig decrypts a stored channel configuration just long enough to
// return a safe preview. Secrets are always replaced before leaving the server.
func (s *Service) MaskedConfig(channel *models.NotificationChannel) map[string]any {
	cfg, err := s.DecryptConfig(channel.ConfigEncrypted)
	if err != nil {
		return map[string]any{}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return map[string]any{}
	}
	return MaskConfig(channel.Type, string(data))
}

func (s *Service) TestChannel(ctx context.Context, channel *models.NotificationChannel) error {
	cfg, err := s.DecryptConfig(channel.ConfigEncrypted)
	if err != nil {
		return err
	}
	msg := Message{
		Event:    "test",
		Subject:  channel.Name,
		Title:    "Domain Manager 测试通知",
		Markdown: "这是一条来自 **Domain Manager** 的测试消息。\n\n通知渠道：`" + channel.Name + "`\n发送时间：" + time.Now().In(s.settings.Location()).Format("2006-01-02 15:04:05"),
	}
	err = s.sender.Send(ctx, channel.Type, cfg, msg)
	now := time.Now()
	updates := map[string]any{"last_test_at": now, "last_test_ok": err == nil, "last_error": ""}
	if err != nil {
		updates["last_error"] = security.SanitizeText(err.Error(), 1000)
	}
	_ = s.db.Model(&models.NotificationChannel{}).Where("id = ?", channel.ID).Updates(updates).Error
	return err
}

func (s *Service) NotifyEvent(ctx context.Context, event, subject, dedupKey, title, content string) int {
	var rule models.NotificationRule
	if err := s.db.Where("event = ?", event).First(&rule).Error; err != nil {
		return 0
	}
	if !rule.Enabled {
		return 0
	}
	var ids []uint
	if err := json.Unmarshal([]byte(rule.ChannelIDs), &ids); err != nil {
		return 0
	}
	if len(ids) == 0 {
		return 0
	}
	var channels []models.NotificationChannel
	if err := s.db.Where("id IN ? AND enabled = ?", ids, true).Find(&channels).Error; err != nil {
		return 0
	}
	sent := 0
	for i := range channels {
		channel := &channels[i]
		if dedupKey != "" {
			var existing models.NotificationLog
			err := s.db.Where("dedup_key = ? AND channel_id = ?", dedupKey, channel.ID).Order("id DESC").First(&existing).Error
			if err == nil {
				skip := true
				if existing.Status == "success" || (existing.Status == "failed" && existing.NextRetryAt == nil) {
					if rule.DedupHours > 0 && time.Since(existing.CreatedAt) >= time.Duration(rule.DedupHours)*time.Hour {
						skip = false
					}
				}
				if skip {
					continue
				}
			}
		}
		now := time.Now()
		log := models.NotificationLog{
			Event: event, Subject: subject, ChannelID: channel.ID, ChannelName: channel.Name,
			DedupKey: dedupKey, Title: title, Content: content, Status: "pending", CreatedAt: now,
		}
		if err := s.db.Create(&log).Error; err != nil {
			logger.L().Error("写入通知日志失败", "error", err)
			continue
		}
		_ = s.attempt(ctx, &log, channel)
		sent++
	}
	return sent
}

func (s *Service) attempt(ctx context.Context, entry *models.NotificationLog, channel *models.NotificationChannel) bool {
	cfg, err := s.DecryptConfig(channel.ConfigEncrypted)
	if err != nil {
		_ = s.finish(entry, false, "渠道配置解密失败: "+err.Error(), false, 1)
		return false
	}
	msg := Message{Event: entry.Event, Subject: entry.Subject, Title: entry.Title, Markdown: entry.Content}
	var lastErr error
	used := 0
	for i := 0; i < 2; i++ {
		sendCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		used++
		lastErr = s.sender.Send(sendCtx, channel.Type, cfg, msg)
		cancel()
		if lastErr == nil {
			_ = s.finish(entry, true, "", false, used)
			return true
		}
		if i == 0 {
			time.Sleep(time.Second)
		}
	}
	maxRetries := s.settings.Int("notification_max_retries")
	if maxRetries <= 0 {
		maxRetries = 5
	}
	canRetry := entry.Attempts+used < maxRetries
	_ = s.finish(entry, false, lastErr.Error(), canRetry, used)
	logger.L().Warn("通知发送失败", "channel", channel.Name, "event", entry.Event, "error", lastErr)
	return false
}

func (s *Service) finish(entry *models.NotificationLog, ok bool, errMsg string, retry bool, used int) error {
	now := time.Now()
	if used < 1 {
		used = 1
	}
	entry.Attempts += used
	updates := map[string]any{
		"attempts": entry.Attempts,
		"error":    security.SanitizeText(errMsg, 1500),
	}
	if ok {
		updates["status"] = "success"
		updates["sent_at"] = now
		updates["next_retry_at"] = nil
		updates["error"] = ""
		entry.Status = "success"
	} else if retry && entry.Attempts < s.maxRetries() {
		delay := time.Duration(5*entry.Attempts) * time.Minute
		if delay < 5*time.Minute {
			delay = 5 * time.Minute
		}
		next := now.Add(delay)
		updates["status"] = "failed"
		updates["next_retry_at"] = next
		entry.Status = "failed"
	} else {
		updates["status"] = "failed"
		updates["next_retry_at"] = nil
		entry.Status = "failed"
	}
	return s.db.Model(&models.NotificationLog{}).Where("id = ?", entry.ID).Updates(updates).Error
}

func (s *Service) maxRetries() int {
	n := s.settings.Int("notification_max_retries")
	if n <= 0 {
		n = 5
	}
	return n
}

func (s *Service) RetryFailed(ctx context.Context) (int, int) {
	now := time.Now()
	var entries []models.NotificationLog
	_ = s.db.Where("status = ? AND attempts < ? AND next_retry_at IS NOT NULL AND next_retry_at <= ?",
		"failed", s.maxRetries(), now).
		Order("id ASC").Limit(20).Find(&entries).Error
	// Also recover notifications whose process died while pending.
	var stale []models.NotificationLog
	_ = s.db.Where("status = ? AND created_at <= ?", "pending", now.Add(-10*time.Minute)).Limit(20).Find(&stale).Error
	entries = append(entries, stale...)
	success, failed := 0, 0
	for i := range entries {
		entry := &entries[i]
		var channel models.NotificationChannel
		if err := s.db.First(&channel, entry.ChannelID).Error; err != nil {
			_ = s.db.Model(entry).Updates(map[string]any{"status": "failed", "error": "通知渠道不存在，无法重试", "next_retry_at": nil}).Error
			failed++
			continue
		}
		if !channel.Enabled {
			_ = s.db.Model(entry).Updates(map[string]any{"status": "failed", "error": "通知渠道已禁用", "next_retry_at": nil}).Error
			failed++
			continue
		}
		if s.attempt(ctx, entry, &channel) {
			success++
		} else {
			failed++
		}
	}
	return success, failed
}

func (s *Service) Rules() ([]models.NotificationRule, error) {
	var rules []models.NotificationRule
	err := s.db.Order("id ASC").Find(&rules).Error
	return rules, err
}

func (s *Service) UpdateRules(rules []models.NotificationRule) error {
	allowed := map[string]bool{
		models.EventDomainExpiry: true, models.EventSSLExpiry: true, models.EventCertIssued: true,
		models.EventCertRenewed: true, models.EventCertFailed: true, models.EventSystemError: true,
		models.EventRecovery: true,
	}
	for _, rule := range rules {
		if !allowed[rule.Event] {
			return errors.New("未知的通知事件类型")
		}
		for _, id := range parseIDs(rule.ChannelIDs) {
			var count int64
			if err := s.db.Model(&models.NotificationChannel{}).Where("id = ?", id).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				return fmt.Errorf("通知渠道 %d 不存在", id)
			}
		}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			if err := tx.Model(&models.NotificationRule{}).Where("event = ?", rule.Event).Updates(map[string]any{
				"channel_ids": rule.ChannelIDs, "enabled": rule.Enabled, "dedup_hours": rule.DedupHours,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func parseIDs(raw string) []uint {
	var ids []uint
	_ = json.Unmarshal([]byte(raw), &ids)
	return ids
}

func (s *Service) RemoveChannelFromRules(channelID uint) {
	var rules []models.NotificationRule
	_ = s.db.Find(&rules).Error
	for _, rule := range rules {
		ids := parseIDs(rule.ChannelIDs)
		out := ids[:0]
		changed := false
		for _, id := range ids {
			if id == channelID {
				changed = true
				continue
			}
			out = append(out, id)
		}
		if changed {
			data, _ := json.Marshal(out)
			_ = s.db.Model(&models.NotificationRule{}).Where("id = ?", rule.ID).Update("channel_ids", string(data)).Error
		}
	}
}

func (s *Service) BuildDomainExpiry(domainName string, expiresAt time.Time, days int) (string, string) {
	title := "【域名到期告警】"
	if days < 0 {
		title = "【域名已过期告警】"
	}
	content := fmt.Sprintf("域名：%s\n\n到期时间：%s\n剩余时间：%d 天\n\n请及时续费，避免域名过期。",
		domainName, expiresAt.In(s.settings.Location()).Format("2006-01-02"), days)
	return title, content
}

func (s *Service) BuildSSLExpiry(domainName, issuer string, expiresAt time.Time, days int) (string, string) {
	title := "【SSL 证书到期告警】"
	if days < 0 {
		title = "【SSL 证书已过期告警】"
	}
	content := fmt.Sprintf("域名：%s\n\n证书颁发机构：%s\n\n证书到期时间：%s\n剩余有效期：%d 天\n\n请及时续期，避免 HTTPS 服务异常。",
		domainName, strings.TrimSpace(issuer), expiresAt.In(s.settings.Location()).Format("2006-01-02"), days)
	return title, content
}
