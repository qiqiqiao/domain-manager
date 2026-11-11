package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

type CheckResult struct {
	Success int
	Failed  int
	Skipped int
}

type DomainService struct {
	db       *gorm.DB
	settings *settings.Manager
	lookup   *DomainLookup
	inFlight sync.Map
}

func NewDomainService(db *gorm.DB, st *settings.Manager) *DomainService {
	return &DomainService{db: db, settings: st, lookup: NewDomainLookup(st)}
}

func (s *DomainService) CheckOne(ctx context.Context, id uint, action string) (*models.Domain, error) {
	var domain models.Domain
	if err := s.db.First(&domain, id).Error; err != nil {
		return nil, err
	}
	if _, loaded := s.inFlight.LoadOrStore(domain.ID, struct{}{}); loaded {
		return &domain, errors.New("该域名正在检测中")
	}
	defer s.inFlight.Delete(domain.ID)

	start := time.Now()
	info, lookupErr := s.lookup.Lookup(ctx, domain.Name)
	now := time.Now()
	updates := map[string]any{"last_checked_at": now}
	if lookupErr != nil {
		updates["last_error"] = security.SanitizeText(lookupErr.Error(), 1000)
	} else {
		updates["last_error"] = ""
	}
	if info != nil {
		if info.Registrar != "" {
			updates["registrar"] = security.SanitizeText(info.Registrar, 255)
		}
		if info.RegisteredAt != nil {
			updates["registered_at"] = *info.RegisteredAt
		}
		if info.ExpiresAt != nil && !domain.ExpiryLocked {
			updates["expires_at"] = *info.ExpiresAt
			updates["expiry_source"] = info.Source
			domain.ExpiresAt = info.ExpiresAt
		}
	}
	if domain.ExpiryLocked {
		updates["expiry_source"] = "manual"
	}
	if domain.ExpiresAt != nil {
		days := security.DaysUntilIn(*domain.ExpiresAt, s.settings.Location())
		status := domainStatus(days, s.settings.Int("domain_warning_days"))
		if lookupErr != nil && !domain.ExpiryLocked {
			status = models.DomainStatusQueryFailed
		}
		updates["days_remaining"] = days
		updates["status"] = status
	} else {
		updates["status"] = models.DomainStatusQueryFailed
		updates["days_remaining"] = 0
		if lookupErr == nil {
			updates["last_error"] = "未能从 RDAP/WHOIS 获取到期时间，可手动设置到期时间"
		}
	}
	if err := s.db.Model(&models.Domain{}).Where("id = ?", domain.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	_ = s.db.First(&domain, domain.ID).Error

	status := "success"
	message := "域名信息查询成功"
	if lookupErr != nil {
		status = "failed"
		message = "域名信息查询失败: " + lookupErr.Error()
	}
	s.log(id, domain.Name, action, status, message, time.Since(start), info)
	logger.L().Info("域名检测完成", "domain", domain.Name, "status", status, "days", domain.DaysRemaining, "error", lookupErr)
	return &domain, nil
}

func (s *DomainService) CheckAll(ctx context.Context, action string) (CheckResult, error) {
	var domains []models.Domain
	if err := s.db.Where("monitor_enabled = ?", true).Find(&domains).Error; err != nil {
		return CheckResult{}, err
	}
	ids := make([]uint, 0, len(domains))
	for _, domain := range domains {
		ids = append(ids, domain.ID)
	}
	return s.CheckIDs(ctx, ids, action), nil
}

func (s *DomainService) CheckIDs(ctx context.Context, ids []uint, action string) CheckResult {
	result := CheckResult{}
	max := s.settings.Int("max_concurrency")
	if max < 1 {
		max = 5
	}
	sem := make(chan struct{}, max)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, id := range ids {
		id := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("检测发生内部异常: %v", r)
						logger.L().Error("域名检测 goroutine panic", "domain_id", id, "panic", r)
					}
				}()
				_, err = s.CheckOne(ctx, id, action)
			}()
			mu.Lock()
			if err != nil {
				if err.Error() == "该域名正在检测中" {
					result.Skipped++
				} else {
					result.Failed++
				}
			} else {
				result.Success++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return result
}

func (s *DomainService) log(id uint, target, action, status, message string, duration time.Duration, info *DomainInfo) {
	entry := models.MonitorLog{
		Kind: "domain", TargetID: id, Target: target, Action: action, Status: status,
		Message: security.SanitizeText(message, 2000), DurationMS: duration.Milliseconds(),
	}
	if info != nil {
		entry.Details = fmt.Sprintf(`{"registrar":%q,"source":%q,"expires_at":%q}`,
			info.Registrar, info.Source, timePtrString(info.ExpiresAt))
	}
	_ = s.db.Create(&entry).Error
}

func timePtrString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func domainStatus(days, warningDays int) string {
	if warningDays <= 0 {
		warningDays = 30
	}
	if days < 0 {
		return models.DomainStatusExpired
	}
	if days <= warningDays {
		return models.DomainStatusExpiring
	}
	return models.DomainStatusNormal
}
