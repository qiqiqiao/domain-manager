package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/settings"

	"github.com/gin-gonic/gin"
)

func (s *Server) getSettings(c *gin.Context) {
	ok(c, gin.H{
		"settings": s.settings.All(),
		"defaults": settings.Defaults(),
	})
}

func (s *Server) updateSettings(c *gin.Context) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		badRequest(c, "配置参数无效")
		return
	}
	if nested, ok := body["settings"].(map[string]any); ok {
		body = nested
	}
	values := make(map[string]string, len(body))
	for key, raw := range body {
		switch v := raw.(type) {
		case string:
			values[key] = v
		case bool:
			values[key] = strconv.FormatBool(v)
		case float64:
			values[key] = strconv.FormatFloat(v, 'f', -1, 64)
		case nil:
			values[key] = ""
		default:
			badRequest(c, fmt.Sprintf("配置项 %s 的值类型无效", key))
			return
		}
	}
	if len(values) == 0 {
		badRequest(c, "没有需要保存的配置")
		return
	}
	if err := s.settings.Update(values); err != nil {
		badRequest(c, err.Error())
		return
	}
	if err := s.settings.Reload(); err != nil {
		serverError(c, err)
		return
	}
	s.auth.RefreshPolicy()
	warning := ""
	if err := s.scheduler.Reload(); err != nil {
		warning = "定时任务重新加载失败: " + err.Error()
	}
	ok(c, gin.H{"settings": s.settings.All(), "warning": warning})
}

func (s *Server) listJobs(c *gin.Context) {
	jobs, err := s.scheduler.Jobs()
	if err != nil {
		serverError(c, err)
		return
	}
	runs, _ := s.scheduler.Runs(20)
	ok(c, gin.H{"jobs": jobs, "recent_runs": runs})
}

func (s *Server) runJob(c *gin.Context) {
	key := strings.TrimSpace(c.Param("key"))
	if key == "" {
		badRequest(c, "任务标识不能为空")
		return
	}
	if err := s.scheduler.RunNow(key); err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusAccepted, response{Code: 0, Message: "任务已触发"})
}

func (s *Server) listJobRuns(c *gin.Context) {
	page, size := pageParams(c)
	query := s.db.Model(&models.JobRun{})
	if key := c.Query("job_key"); key != "" {
		query = query.Where("job_key = ?", key)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		serverError(c, err)
		return
	}
	var items []models.JobRun
	if err := query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	ok(c, paginated(items, total, page, size))
}

func (s *Server) systemStatus(c *gin.Context) {
	dbInfo := gin.H{}
	if sqlDB, err := s.db.DB(); err == nil {
		stats := sqlDB.Stats()
		dbInfo = gin.H{
			"open_connections": stats.OpenConnections, "in_use": stats.InUse,
			"idle": stats.Idle, "max_open": stats.MaxOpenConnections,
		}
	}
	fileInfo, _ := os.Stat(s.cfg.DBPath)
	size := int64(0)
	if fileInfo != nil {
		size = fileInfo.Size()
	}
	var domainCount, certCount, channelCount int64
	s.db.Model(&models.Domain{}).Count(&domainCount)
	s.db.Model(&models.SSLCertificate{}).Count(&certCount)
	s.db.Model(&models.NotificationChannel{}).Count(&channelCount)
	ok(c, gin.H{
		"version": s.version, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()), "started_at": s.startedAt,
		"database_path": s.cfg.DBPath, "database_size": size, "database": dbInfo,
		"domain_count": domainCount, "certificate_count": certCount, "notification_channel_count": channelCount,
		"acme_staging": s.settings.Bool("acme_staging"),
		"listen":       s.cfg.ListenAddr(),
	})
}

type backupRequest struct {
	Full     bool   `json:"full"`
	Password string `json:"password"`
}

func (s *Server) backup(c *gin.Context) {
	var req backupRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			badRequest(c, "备份参数无效")
			return
		}
	}
	dir := filepath.Join(s.cfg.DataDir, "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		serverError(c, err)
		return
	}
	stamp := time.Now().Format("20060102-150405")
	if req.Full {
		if len([]rune(req.Password)) < 8 {
			badRequest(c, "完整备份口令至少需要 8 个字符")
			return
		}
		name := "domain-manager-full-" + stamp + ".dmbak"
		path := filepath.Join(dir, name)
		defer os.Remove(path)
		if err := database.FullBackup(s.db, s.cfg.DataDir, path, req.Password); err != nil {
			serverError(c, err)
			return
		}
		c.Header("X-Backup-Scope", "full-data-encrypted")
		c.FileAttachment(path, name)
		return
	}
	name := "domain-manager-" + stamp + ".db"
	path := filepath.Join(dir, name)
	defer os.Remove(path)
	if err := database.Backup(s.db, path); err != nil {
		serverError(c, err)
		return
	}
	c.Header("X-Backup-Scope", "sqlite-database")
	c.FileAttachment(path, name)
}

func (s *Server) restore(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		badRequest(c, "请上传备份文件")
		return
	}
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	switch ext {
	case ".db", ".sqlite", ".sqlite3", ".dmbak", ".dmbackup":
	default:
		badRequest(c, "仅支持 .db / .sqlite / .sqlite3 数据库备份或 .dmbak 完整备份")
		return
	}
	if fileHeader.Size > 4*1024*1024*1024 {
		badRequest(c, "备份文件不能超过 4GB")
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		serverError(c, err)
		return
	}
	f, err := fileHeader.Open()
	if err != nil {
		badRequest(c, "读取上传文件失败")
		return
	}
	defer f.Close()
	temp, err := os.CreateTemp(dir, "restore-*"+ext)
	if err != nil {
		serverError(c, err)
		return
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	_ = temp.Chmod(0o600)
	if _, err := temp.ReadFrom(http.MaxBytesReader(c.Writer, f, 4*1024*1024*1024)); err != nil {
		temp.Close()
		badRequest(c, "备份文件读取失败或超过大小限制")
		return
	}
	temp.Close()

	full, err := database.IsFullBackup(tempPath)
	if err != nil {
		badRequest(c, "无法识别备份文件")
		return
	}
	password := c.PostForm("password")

	// Stop new scheduled jobs while tables/files are being replaced. Running
	// jobs are given a short grace period, then the restore continues.
	s.scheduler.Pause(5 * time.Second)
	resumed := false
	resume := func() {
		if !resumed {
			resumed = true
			_ = s.scheduler.Reload()
		}
	}
	defer resume()

	if full {
		if len([]rune(password)) < 8 {
			badRequest(c, "完整备份需要输入备份口令")
			return
		}
		if err := database.RestoreFull(s.db, tempPath, s.cfg.DataDir, password); err != nil {
			badRequest(c, err.Error())
			return
		}
		if err := s.cipher.ReloadFromFile(filepath.Join(s.cfg.DataDir, "secret.key")); err != nil {
			serverError(c, fmt.Errorf("恢复后重新加载加密密钥失败，请重启服务: %w", err))
			return
		}
	} else if err := database.Restore(s.db, tempPath); err != nil {
		badRequest(c, err.Error())
		return
	}
	if err := database.RebasePaths(s.db, s.cfg.DataDir); err != nil {
		c.Error(err)
	}
	if err := s.settings.Reload(); err != nil {
		serverError(c, err)
		return
	}
	s.auth.RefreshPolicy()
	resume()
	s.sessions.DeleteAll()
	s.clearSessionCookie(c)
	ok(c, gin.H{"restored": true, "full": full, "reauth_required": true})
}
