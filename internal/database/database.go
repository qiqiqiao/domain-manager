package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type InitialAdmin struct {
	Username string
	Password string
	Created  bool
	FromEnv  bool
}

func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:  gormlogger.Default.LogMode(gormlogger.Warn),
		NowFunc: func() time.Time { return time.Now().Local() },
	})
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(5)
	sqlDB.SetMaxIdleConns(3)
	sqlDB.SetConnMaxLifetime(time.Hour)
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("连接 SQLite 失败: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return db, nil
}

func Migrate(db *gorm.DB) error {
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return err
	}
	if err := db.AutoMigrate(
		&models.Domain{},
		&models.SSLCertificate{},
		&models.NotificationChannel{},
		&models.NotificationRule{},
		&models.NotificationLog{},
		&models.MonitorLog{},
		&models.ACMEAccount{},
		&models.CertificateOrder{},
		&models.SystemSetting{},
		&models.ScheduledJob{},
		&models.JobRun{},
		&models.AlertState{},
		&models.User{},
		&models.SchemaMigration{},
	); err != nil {
		return fmt.Errorf("数据库迁移失败: %w", err)
	}

	migrations := []struct {
		Version string
		Run     func(*gorm.DB) error
	}{
		{"2026111001_initial", func(tx *gorm.DB) error {
			indexes := []string{
				"CREATE INDEX IF NOT EXISTS idx_domains_status_expiry ON domains(status, expires_at)",
				"CREATE INDEX IF NOT EXISTS idx_certs_status_expiry ON ssl_certificates(status, not_after)",
				"CREATE INDEX IF NOT EXISTS idx_monitor_logs_created ON monitor_logs(created_at)",
				"CREATE INDEX IF NOT EXISTS idx_notification_logs_created ON notification_logs(created_at)",
				"CREATE INDEX IF NOT EXISTS idx_orders_status_retry ON certificate_orders(status, next_retry_at)",
			}
			for _, sql := range indexes {
				if err := tx.Exec(sql).Error; err != nil {
					return err
				}
			}
			return nil
		}},
	}
	for _, migration := range migrations {
		var count int64
		if err := db.Model(&models.SchemaMigration{}).Where("version = ?", migration.Version).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if err := db.Transaction(migration.Run); err != nil {
			return fmt.Errorf("执行迁移 %s 失败: %w", migration.Version, err)
		}
		if err := db.Create(&models.SchemaMigration{Version: migration.Version, AppliedAt: time.Now()}).Error; err != nil {
			return err
		}
	}
	return nil
}

func SeedRules(db *gorm.DB) error {
	rules := []models.NotificationRule{
		{Event: models.EventDomainExpiry, ChannelIDs: "[]", Enabled: true, DedupHours: 24, Description: "域名即将到期或已过期"},
		{Event: models.EventSSLExpiry, ChannelIDs: "[]", Enabled: true, DedupHours: 24, Description: "SSL 证书即将到期或已过期"},
		{Event: models.EventCertIssued, ChannelIDs: "[]", Enabled: true, DedupHours: 0, Description: "证书申请成功"},
		{Event: models.EventCertRenewed, ChannelIDs: "[]", Enabled: true, DedupHours: 0, Description: "证书续期成功"},
		{Event: models.EventCertFailed, ChannelIDs: "[]", Enabled: true, DedupHours: 0, Description: "证书申请或续期失败"},
		{Event: models.EventSystemError, ChannelIDs: "[]", Enabled: true, DedupHours: 1, Description: "系统任务异常"},
		{Event: models.EventRecovery, ChannelIDs: "[]", Enabled: true, DedupHours: 0, Description: "告警恢复通知"},
	}
	for _, rule := range rules {
		var count int64
		if err := db.Model(&models.NotificationRule{}).Where("event = ?", rule.Event).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if err := db.Create(&rule).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func DefaultJobs() []models.ScheduledJob {
	return []models.ScheduledJob{
		{Key: "domain_check", Name: "域名到期检查", Cron: "0 3 * * *", Enabled: true},
		{Key: "ssl_check", Name: "SSL 证书检测", Cron: "0 */6 * * *", Enabled: true},
		{Key: "renewal_check", Name: "证书续期检查", Cron: "0 4 * * *", Enabled: true},
		{Key: "alert_scan", Name: "告警扫描", Cron: "0 * * * *", Enabled: true},
		{Key: "notification_retry", Name: "通知重试", Cron: "*/10 * * * *", Enabled: true},
		{Key: "acme_worker", Name: "证书订单队列", Cron: "*/5 * * * *", Enabled: true},
		{Key: "log_cleanup", Name: "日志清理", Cron: "30 3 * * *", Enabled: true},
	}
}

func SeedJobs(db *gorm.DB) error {
	for _, job := range DefaultJobs() {
		var count int64
		if err := db.Model(&models.ScheduledJob{}).Where("key = ?", job.Key).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if err := db.Create(&job).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func SeedAdmin(db *gorm.DB) (*InitialAdmin, error) {
	var count int64
	if err := db.Model(&models.User{}).Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return &InitialAdmin{Created: false}, nil
	}
	username := strings.TrimSpace(os.Getenv("DM_ADMIN_USER"))
	if username == "" {
		username = "admin"
	}
	password := os.Getenv("DM_ADMIN_PASSWORD")
	fromEnv := password != ""
	if password == "" {
		var err error
		password, err = security.RandomPassword(20)
		if err != nil {
			return nil, err
		}
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("初始化管理员密码失败: %w", err)
	}
	user := models.User{
		Username:           username,
		PasswordHash:       hash,
		Role:               "admin",
		Active:             true,
		MustChangePassword: true,
	}
	if err := db.Create(&user).Error; err != nil {
		return nil, err
	}
	logger.L().Info("已创建初始管理员账号", "username", username)
	return &InitialAdmin{Username: username, Password: password, Created: true, FromEnv: fromEnv}, nil
}

// Backup creates a consistent online snapshot using SQLite VACUUM INTO.
func Backup(db *gorm.DB, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	_ = os.Remove(dest)
	quoted := strings.ReplaceAll(dest, "'", "''")
	if err := db.Exec("VACUUM INTO '" + quoted + "'").Error; err != nil {
		return fmt.Errorf("创建数据库备份失败: %w", err)
	}
	return os.Chmod(dest, 0o600)
}

var restoreTables = []string{
	"users", "notification_channels", "notification_rules", "notification_logs",
	"alert_states", "domains", "ssl_certificates", "acme_accounts", "certificate_orders",
	"monitor_logs", "scheduled_jobs", "job_runs", "system_settings", "schema_migrations",
}

// Restore validates a SQLite backup and copies its data into the live database
// on a single connection. A failed restore is rolled back.
func Restore(db *gorm.DB, source string) error {
	header := make([]byte, 16)
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	_, err = f.Read(header)
	f.Close()
	if err != nil || string(header) != "SQLite format 3\x00" {
		return errors.New("上传文件不是有效的 SQLite 数据库")
	}
	if fi, err := os.Stat(source); err != nil || fi.Size() > 512*1024*1024 {
		return errors.New("备份文件无效或超过 512MB")
	}

	return db.Connection(func(conn *gorm.DB) error {
		if err := conn.Exec("ATTACH DATABASE ? AS restore", source).Error; err != nil {
			return fmt.Errorf("挂载备份数据库失败: %w", err)
		}
		defer conn.Exec("DETACH DATABASE restore")

		var tables []string
		for _, table := range restoreTables {
			var n int64
			if err := conn.Raw("SELECT count(*) FROM restore.sqlite_master WHERE type='table' AND name=?", table).Scan(&n).Error; err != nil {
				return fmt.Errorf("检查备份数据表 %s 失败: %w", table, err)
			}
			if n == 0 {
				// Older backups may not contain tables added by newer versions.
				logger.L().Warn("备份数据库缺少数据表，已跳过", "table", table)
				continue
			}
			tables = append(tables, table)
		}
		if len(tables) == 0 {
			return errors.New("备份数据库缺少可恢复的数据表")
		}

		var integrity string
		if err := conn.Raw("PRAGMA restore.integrity_check").Scan(&integrity).Error; err != nil || integrity != "ok" {
			return errors.New("备份数据库完整性检查失败")
		}

		if err := conn.Exec("PRAGMA foreign_keys=OFF").Error; err != nil {
			return err
		}
		defer conn.Exec("PRAGMA foreign_keys=ON")

		return conn.Transaction(func(tx *gorm.DB) error {
			for _, table := range tables {
				quoted := `"` + table + `"`
				liveCols, err := queryColumns(tx, "SELECT * FROM "+quoted+" LIMIT 0")
				if err != nil {
					return fmt.Errorf("读取表 %s 结构失败: %w", table, err)
				}
				backupCols, err := queryColumns(tx, "SELECT * FROM restore."+quoted+" LIMIT 0")
				if err != nil {
					return fmt.Errorf("读取备份表 %s 结构失败: %w", table, err)
				}
				cols := intersectColumns(liveCols, backupCols)
				if len(cols) == 0 {
					logger.L().Warn("备份表与当前表没有共同列，已跳过", "table", table)
					continue
				}
				quotedCols := quoteColumns(cols)
				if err := tx.Exec("DELETE FROM " + quoted).Error; err != nil {
					return fmt.Errorf("清理表 %s 失败: %w", table, err)
				}
				sql := "INSERT INTO " + quoted + " (" + quotedCols + ") SELECT " + quotedCols + " FROM restore." + quoted
				if err := tx.Exec(sql).Error; err != nil {
					return fmt.Errorf("恢复表 %s 失败: %w", table, err)
				}
			}
			return nil
		})
	})
}
