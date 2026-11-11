package api

import (
	"time"

	"domain-manager/internal/models"

	"github.com/gin-gonic/gin"
)

type statusCountRow struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

func (s *Server) dashboard(c *gin.Context) {
	loc := s.settings.Location()
	now := time.Now().In(loc)
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	startTrend := startOfDay.AddDate(0, 0, -29)

	counts := gin.H{}
	var domainTotal, domainNormal, domainExpiring, domainExpired, domainFailed, domainPending int64
	s.db.Model(&models.Domain{}).Count(&domainTotal)
	s.db.Model(&models.Domain{}).Where("status = ?", models.DomainStatusNormal).Count(&domainNormal)
	s.db.Model(&models.Domain{}).Where("status = ?", models.DomainStatusExpiring).Count(&domainExpiring)
	s.db.Model(&models.Domain{}).Where("status = ?", models.DomainStatusExpired).Count(&domainExpired)
	s.db.Model(&models.Domain{}).Where("status = ?", models.DomainStatusQueryFailed).Count(&domainFailed)
	s.db.Model(&models.Domain{}).Where("status = ?", models.DomainStatusPending).Count(&domainPending)

	var sslTotal, sslNormal, sslExpiring, sslExpired, sslInvalid, httpsAbnormal int64
	s.db.Model(&models.SSLCertificate{}).Count(&sslTotal)
	s.db.Model(&models.SSLCertificate{}).Where("status = ?", models.CertStatusNormal).Count(&sslNormal)
	s.db.Model(&models.SSLCertificate{}).Where("status = ?", models.CertStatusExpiring).Count(&sslExpiring)
	s.db.Model(&models.SSLCertificate{}).Where("status = ?", models.CertStatusExpired).Count(&sslExpired)
	s.db.Model(&models.SSLCertificate{}).Where("status = ?", models.CertStatusInvalid).Count(&sslInvalid)
	s.db.Model(&models.SSLCertificate{}).Where("monitor_enabled = ? AND (https_status NOT IN ? OR status IN ?)",
		true, []string{"ok", "unknown", "not_checked"}, []string{models.CertStatusUnreachable, models.CertStatusFailed, models.CertStatusInvalid, models.CertStatusExpired}).Count(&httpsAbnormal)

	var todayChecks, todayAlerts int64
	s.db.Model(&models.MonitorLog{}).Where("created_at >= ? AND kind IN ?", startOfDay, []string{"domain", "ssl"}).Count(&todayChecks)
	s.db.Model(&models.NotificationLog{}).Where("created_at >= ? AND event IN ?", startOfDay,
		[]string{models.EventDomainExpiry, models.EventSSLExpiry, models.EventRecovery}).Count(&todayAlerts)

	counts["domain_total"] = domainTotal
	counts["domain_normal"] = domainNormal
	counts["domain_expiring"] = domainExpiring
	counts["domain_expired"] = domainExpired
	counts["domain_failed"] = domainFailed
	counts["domain_pending"] = domainPending
	counts["ssl_total"] = sslTotal
	counts["ssl_normal"] = sslNormal
	counts["ssl_expiring"] = sslExpiring
	counts["ssl_expired"] = sslExpired
	counts["ssl_invalid"] = sslInvalid
	counts["https_abnormal"] = httpsAbnormal
	counts["today_checks"] = todayChecks
	counts["today_alerts"] = todayAlerts

	domainStatus := make([]statusCountRow, 0)
	s.db.Model(&models.Domain{}).Select("status, count(*) as count").Group("status").Scan(&domainStatus)
	sslStatus := make([]statusCountRow, 0)
	s.db.Model(&models.SSLCertificate{}).Select("status, count(*) as count").Group("status").Scan(&sslStatus)

	type trendRow struct {
		Day    string
		Kind   string
		Total  int64
		Failed int64
	}
	var rows []trendRow
	s.db.Model(&models.MonitorLog{}).
		Select("substr(created_at, 1, 10) as day, kind, count(*) as total, sum(case when status = 'failed' then 1 else 0 end) as failed").
		Where("created_at >= ? AND kind IN ?", startTrend, []string{"domain", "ssl"}).
		Group("day, kind").Scan(&rows)
	domainTrend := map[string]int64{}
	sslTrend := map[string]int64{}
	failedTrend := map[string]int64{}
	for _, row := range rows {
		if row.Kind == "domain" {
			domainTrend[row.Day] += row.Total
		} else if row.Kind == "ssl" {
			sslTrend[row.Day] += row.Total
		}
		failedTrend[row.Day] += row.Failed
	}
	dates := make([]string, 0, 30)
	domainSeries := make([]int64, 0, 30)
	sslSeries := make([]int64, 0, 30)
	failedSeries := make([]int64, 0, 30)
	for i := 0; i < 30; i++ {
		day := startTrend.AddDate(0, 0, i).Format("2006-01-02")
		dates = append(dates, day)
		domainSeries = append(domainSeries, domainTrend[day])
		sslSeries = append(sslSeries, sslTrend[day])
		failedSeries = append(failedSeries, failedTrend[day])
	}

	var upcomingDomains []models.Domain
	s.db.Where("expires_at IS NOT NULL AND expires_at >= ? AND expires_at <= ?", startOfDay, startOfDay.AddDate(0, 0, 30)).
		Order("expires_at ASC").Limit(20).Find(&upcomingDomains)
	for i := range upcomingDomains {
		upcomingDomains[i].DaysRemaining = computeDays(upcomingDomains[i].ExpiresAt)
	}
	var upcomingCerts []models.SSLCertificate
	s.db.Where("not_after IS NOT NULL AND not_after >= ? AND not_after <= ?", startOfDay, startOfDay.AddDate(0, 0, 30)).
		Order("not_after ASC").Limit(20).Find(&upcomingCerts)
	certItems := make([]gin.H, 0, len(upcomingCerts))
	for i := range upcomingCerts {
		certItems = append(certItems, certView(&upcomingCerts[i]))
	}

	var recentAlerts []models.NotificationLog
	s.db.Where("event IN ?", []string{models.EventDomainExpiry, models.EventSSLExpiry, models.EventRecovery, models.EventCertFailed, models.EventSystemError}).
		Order("id DESC").Limit(10).Find(&recentAlerts)

	ok(c, gin.H{
		"counts":        counts,
		"domain_status": domainStatus,
		"ssl_status":    sslStatus,
		"trends": gin.H{
			"dates": dates, "domain": domainSeries, "ssl": sslSeries, "failed": failedSeries,
		},
		"upcoming_domains": upcomingDomains,
		"upcoming_certs":   certItems,
		"recent_alerts":    recentAlerts,
	})
}
