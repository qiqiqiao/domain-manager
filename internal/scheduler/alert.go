package scheduler

import (
	"context"
	"fmt"
	"sort"
	"time"

	"domain-manager/internal/models"
	"domain-manager/internal/notification"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

type AlertScanner struct {
	db       *gorm.DB
	settings *settings.Manager
	notifier *notification.Service
}

type AlertResult struct {
	DomainAlerts int
	SSLAlerts    int
	Recovery     int
}

func (a *AlertScanner) Scan(ctx context.Context) (AlertResult, error) {
	result := AlertResult{}
	loc := a.settings.Location()
	domainThresholds := a.settings.Thresholds("domain_expiry_thresholds")
	sslThresholds := a.settings.Thresholds("ssl_expiry_thresholds")

	var domains []models.Domain
	if err := a.db.Where("monitor_enabled = ? AND expires_at IS NOT NULL", true).Find(&domains).Error; err != nil {
		return result, err
	}
	for i := range domains {
		domain := &domains[i]
		days := security.DaysUntilIn(*domain.ExpiresAt, loc)
		threshold, alerting := pickThreshold(days, domainThresholds)
		var state models.AlertState
		found := a.db.Where("subject_type = ? AND subject_id = ? AND alert_type = ?", "domain", domain.ID, "expiry").First(&state).Error == nil
		if alerting {
			if found && state.Active && state.LastThreshold == threshold && sameDate(state.LastExpiry, domain.ExpiresAt) {
				continue
			}
			title, content := a.notifier.BuildDomainExpiry(domain.Name, *domain.ExpiresAt, days)
			dedup := fmt.Sprintf("domain_expiry:%d:%d:%s", domain.ID, threshold, domain.ExpiresAt.In(loc).Format("20060102"))
			dispatched := a.notifier.NotifyEvent(ctx, models.EventDomainExpiry, domain.Name, dedup, title, content)
			if dispatched > 0 {
				result.DomainAlerts++
			}
			if dispatched > 0 || state.Active {
				state.SubjectType, state.SubjectID, state.AlertType = "domain", domain.ID, "expiry"
				state.Active = true
				state.LastThreshold = threshold
				state.LastExpiry = domain.ExpiresAt
				now := time.Now()
				state.LastNotifiedAt = &now
				if err := a.db.Save(&state).Error; err != nil {
					return result, err
				}
			}
		} else if found && state.Active {
			title := "【域名告警恢复】"
			content := fmt.Sprintf("域名：%s\n当前到期时间：%s\n剩余时间：%d 天\n\n域名到期风险已解除。",
				domain.Name, domain.ExpiresAt.In(loc).Format("2006-01-02"), days)
			dedup := fmt.Sprintf("domain_recovery:%d:%s", domain.ID, time.Now().In(loc).Format("20060102"))
			a.notifier.NotifyEvent(ctx, models.EventRecovery, domain.Name, dedup, title, content)
			state.Active = false
			_ = a.db.Save(&state).Error
			result.Recovery++
		}
	}

	var certs []models.SSLCertificate
	if err := a.db.Where("(monitor_enabled = ? OR managed = ?) AND not_after IS NOT NULL", true, true).Find(&certs).Error; err != nil {
		return result, err
	}
	for i := range certs {
		cert := &certs[i]
		days := security.DaysUntilIn(*cert.NotAfter, loc)
		threshold, alerting := pickThreshold(days, sslThresholds)
		var state models.AlertState
		found := a.db.Where("subject_type = ? AND subject_id = ? AND alert_type = ?", "ssl", cert.ID, "expiry").First(&state).Error == nil
		if alerting {
			if found && state.Active && state.LastThreshold == threshold && sameDate(state.LastExpiry, cert.NotAfter) {
				continue
			}
			title, content := a.notifier.BuildSSLExpiry(cert.Domain, cert.Issuer, *cert.NotAfter, days)
			dedup := fmt.Sprintf("ssl_expiry:%d:%d:%s", cert.ID, threshold, cert.NotAfter.In(loc).Format("20060102"))
			dispatched := a.notifier.NotifyEvent(ctx, models.EventSSLExpiry, cert.Domain, dedup, title, content)
			if dispatched > 0 {
				result.SSLAlerts++
			}
			if dispatched > 0 || state.Active {
				state.SubjectType, state.SubjectID, state.AlertType = "ssl", cert.ID, "expiry"
				state.Active = true
				state.LastThreshold = threshold
				state.LastExpiry = cert.NotAfter
				now := time.Now()
				state.LastNotifiedAt = &now
				if err := a.db.Save(&state).Error; err != nil {
					return result, err
				}
			}
		} else if found && state.Active {
			title := "【SSL 证书告警恢复】"
			content := fmt.Sprintf("域名：%s\n当前证书到期时间：%s\n剩余时间：%d 天\n\nSSL 证书到期风险已解除。",
				cert.Domain, cert.NotAfter.In(loc).Format("2006-01-02"), days)
			dedup := fmt.Sprintf("ssl_recovery:%d:%s", cert.ID, time.Now().In(loc).Format("20060102"))
			a.notifier.NotifyEvent(ctx, models.EventRecovery, cert.Domain, dedup, title, content)
			state.Active = false
			_ = a.db.Save(&state).Error
			result.Recovery++
		}
	}
	return result, nil
}

func pickThreshold(days int, thresholds []int) (int, bool) {
	if len(thresholds) == 0 {
		return 0, false
	}
	vals := append([]int(nil), thresholds...)
	sort.Ints(vals)
	if days <= 0 {
		return 0, true
	}
	for _, t := range vals {
		if days <= t {
			return t, true
		}
	}
	return 0, false
}

func sameDate(a, b *time.Time) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Year() == b.Year() && a.YearDay() == b.YearDay()
}
