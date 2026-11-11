package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"domain-manager/internal/acme"
	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/monitor"
	"domain-manager/internal/notification"
	"domain-manager/internal/settings"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

type Scheduler struct {
	db       *gorm.DB
	settings *settings.Manager
	domains  *monitor.DomainService
	ssl      *monitor.SSLService
	acme     *acme.Service
	notifier *notification.Service
	alerts   *AlertScanner

	mu      sync.Mutex
	cron    *cron.Cron
	entries map[string]cron.EntryID
	running sync.Map
}

func New(db *gorm.DB, st *settings.Manager, domains *monitor.DomainService, ssl *monitor.SSLService, acmeSvc *acme.Service, notifier *notification.Service) *Scheduler {
	s := &Scheduler{
		db: db, settings: st, domains: domains, ssl: ssl, acme: acmeSvc, notifier: notifier,
		entries: make(map[string]cron.EntryID),
	}
	s.alerts = &AlertScanner{db: db, settings: st, notifier: notifier}
	return s
}

func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Scheduler) startLocked() error {
	location := s.settings.Location()
	c := cron.New(cron.WithLocation(location), cron.WithChain(cron.Recover(cron.DefaultLogger)))
	s.entries = make(map[string]cron.EntryID)

	definitions := map[string]func(context.Context) (string, error){
		"domain_check":       s.jobDomainCheck,
		"ssl_check":          s.jobSSLCheck,
		"renewal_check":      s.jobRenewalCheck,
		"alert_scan":         s.jobAlertScan,
		"notification_retry": s.jobNotificationRetry,
		"acme_worker":        s.jobACMECheck,
		"log_cleanup":        s.jobLogCleanup,
	}
	var jobs []models.ScheduledJob
	if err := s.db.Find(&jobs).Error; err != nil {
		return err
	}
	for _, job := range jobs {
		spec := s.specFor(job)
		fn, ok := definitions[job.Key]
		if !ok {
			continue
		}
		if job.Cron != spec {
			_ = s.db.Model(&models.ScheduledJob{}).Where("id = ?", job.ID).Update("cron", spec).Error
		}
		if !job.Enabled {
			continue
		}
		key := job.Key
		id, err := c.AddFunc(spec, func() {
			s.run(key, fn)
		})
		if err != nil {
			logger.L().Error("注册定时任务失败", "job", key, "cron", spec, "error", err)
			continue
		}
		s.entries[key] = id
	}
	c.Start()
	s.cron = c
	for key, entryID := range s.entries {
		if entry := c.Entry(entryID); entry.Valid() {
			next := entry.Next
			_ = s.db.Model(&models.ScheduledJob{}).Where("key = ?", key).Update("next_run_at", next).Error
		}
	}
	logger.L().Info("定时任务调度器已启动", "jobs", len(s.entries))
	return nil
}

func (s *Scheduler) specFor(job models.ScheduledJob) string {
	switch job.Key {
	case "domain_check":
		return s.settings.Get("domain_check_cron")
	case "ssl_check":
		return s.settings.Get("ssl_check_cron")
	case "renewal_check":
		return s.settings.Get("renewal_check_cron")
	case "alert_scan":
		return s.settings.Get("alert_scan_cron")
	case "notification_retry":
		return s.settings.Get("notification_retry_cron")
	case "acme_worker":
		return "*/5 * * * *"
	default:
		return job.Cron
	}
}

func (s *Scheduler) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron != nil {
		ctx := s.cron.Stop()
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
	return s.startLocked()
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron != nil {
		s.cron.Stop()
	}
}

// Pause stops scheduling new jobs and waits briefly for in-flight jobs. It is
// used before a restore replaces database and certificate files.
func (s *Scheduler) Pause(grace time.Duration) {
	s.mu.Lock()
	if s.cron != nil {
		ctx := s.cron.Stop()
		select {
		case <-ctx.Done():
		case <-time.After(grace):
		}
	}
	s.mu.Unlock()
	deadline := time.Now().Add(grace)
	for {
		running := false
		s.running.Range(func(_, _ any) bool {
			running = true
			return false
		})
		if !running || time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Scheduler) RunNow(key string) error {
	fns := map[string]func(context.Context) (string, error){
		"domain_check":       s.jobDomainCheck,
		"ssl_check":          s.jobSSLCheck,
		"renewal_check":      s.jobRenewalCheck,
		"alert_scan":         s.jobAlertScan,
		"notification_retry": s.jobNotificationRetry,
		"acme_worker":        s.jobACMECheck,
		"log_cleanup":        s.jobLogCleanup,
	}
	fn, ok := fns[key]
	if !ok {
		return errors.New("未知任务")
	}
	go s.run(key, fn)
	return nil
}

func (s *Scheduler) run(key string, fn func(context.Context) (string, error)) {
	if _, loaded := s.running.LoadOrStore(key, true); loaded {
		logger.L().Warn("定时任务已在执行，跳过本次调度", "job", key)
		return
	}
	defer s.running.Delete(key)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	status := "success"
	message := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				status = "failed"
				message = fmt.Sprintf("任务发生 panic: %v", r)
				logger.L().Error("定时任务 panic", "job", key, "panic", r)
			}
		}()
		msg, err := fn(ctx)
		if err != nil {
			status = "failed"
			message = err.Error()
		} else {
			message = msg
		}
	}()
	duration := time.Since(start)
	now := time.Now()
	_ = s.db.Create(&models.JobRun{
		JobKey: key, Status: status, Message: message, DurationMS: duration.Milliseconds(),
		StartedAt: start, FinishedAt: now,
	}).Error
	updates := map[string]any{
		"last_run_at": now, "last_status": status, "last_error": message,
		"last_duration_ms": duration.Milliseconds(),
	}
	s.mu.Lock()
	if id, ok := s.entries[key]; ok && s.cron != nil {
		if entry := s.cron.Entry(id); entry.Valid() {
			updates["next_run_at"] = entry.Next
		}
	}
	s.mu.Unlock()
	_ = s.db.Model(&models.ScheduledJob{}).Where("key = ?", key).Updates(updates).Error
	if status == "failed" {
		logger.L().Error("定时任务失败", "job", key, "duration", duration, "error", message)
		s.notifier.NotifyEvent(context.Background(), models.EventSystemError, key,
			fmt.Sprintf("system_job:%s:%s", key, now.Format("2006010215")),
			"【系统任务异常】",
			fmt.Sprintf("任务：%s\n时间：%s\n错误：%s", key, now.Format("2006-01-02 15:04:05"), message))
	} else {
		logger.L().Info("定时任务完成", "job", key, "duration", duration, "message", message)
	}
}

func (s *Scheduler) jobDomainCheck(ctx context.Context) (string, error) {
	result, err := s.domains.CheckAll(ctx, "scheduled")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("域名检测完成：成功 %d，失败 %d，跳过 %d", result.Success, result.Failed, result.Skipped), nil
}

func (s *Scheduler) jobSSLCheck(ctx context.Context) (string, error) {
	result, err := s.ssl.CheckAll(ctx, "scheduled")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("SSL 检测完成：成功 %d，失败 %d，跳过 %d", result.Success, result.Failed, result.Skipped), nil
}

func (s *Scheduler) jobRenewalCheck(ctx context.Context) (string, error) {
	count, err := s.acme.RenewDue(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("已创建 %d 个自动续期订单", count), nil
}

func (s *Scheduler) jobAlertScan(ctx context.Context) (string, error) {
	result, err := s.alerts.Scan(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("告警扫描完成：域名 %d 条，证书 %d 条，恢复 %d 条", result.DomainAlerts, result.SSLAlerts, result.Recovery), nil
}

func (s *Scheduler) jobNotificationRetry(ctx context.Context) (string, error) {
	success, failed := s.notifier.RetryFailed(ctx)
	return fmt.Sprintf("通知重试完成：成功 %d，失败 %d", success, failed), nil
}

func (s *Scheduler) jobACMECheck(ctx context.Context) (string, error) {
	count, err := s.acme.RetryDue(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("证书订单队列处理：提交 %d 个订单", count), nil
}

func (s *Scheduler) jobLogCleanup(ctx context.Context) (string, error) {
	days := s.settings.Int("log_retention_days")
	if days <= 0 {
		days = 90
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	monitor := s.db.Where("created_at < ?", cutoff).Delete(&models.MonitorLog{})
	if monitor.Error != nil {
		return "", monitor.Error
	}
	notifications := s.db.Where("created_at < ?", cutoff).Delete(&models.NotificationLog{})
	if notifications.Error != nil {
		return "", notifications.Error
	}
	runs := s.db.Where("started_at < ?", cutoff).Delete(&models.JobRun{})
	if runs.Error != nil {
		return "", runs.Error
	}
	monitorLogs, notificationLogs, jobRuns := monitor.RowsAffected, notifications.RowsAffected, runs.RowsAffected
	_ = ctx
	return fmt.Sprintf("日志清理完成：保留 %d 天，监控日志 %d 条，通知日志 %d 条，任务记录 %d 条",
		days, monitorLogs, notificationLogs, jobRuns), nil
}

func (s *Scheduler) Jobs() ([]models.ScheduledJob, error) {
	var jobs []models.ScheduledJob
	err := s.db.Order("id ASC").Find(&jobs).Error
	return jobs, err
}

func (s *Scheduler) Runs(limit int) ([]models.JobRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var runs []models.JobRun
	err := s.db.Order("id DESC").Limit(limit).Find(&runs).Error
	return runs, err
}
