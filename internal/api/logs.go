package api

import (
	"strings"
	"time"

	"domain-manager/internal/models"

	"github.com/gin-gonic/gin"
)

func (s *Server) listMonitorLogs(c *gin.Context) {
	page, size := pageParams(c)
	query := s.db.Model(&models.MonitorLog{})
	if kind := strings.TrimSpace(c.Query("kind")); kind != "" {
		query = query.Where("kind = ?", kind)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if target := strings.TrimSpace(c.Query("target")); target != "" {
		query = query.Where("target LIKE ?", "%"+target+"%")
	}
	if start := strings.TrimSpace(c.Query("start")); start != "" {
		if t, err := parseDateIn(start, s.settings.Location()); err == nil && t != nil {
			query = query.Where("created_at >= ?", t)
		}
	}
	if end := strings.TrimSpace(c.Query("end")); end != "" {
		if t, err := parseDateIn(end, s.settings.Location()); err == nil && t != nil {
			query = query.Where("created_at < ?", t.Add(24*time.Hour))
		}
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		serverError(c, err)
		return
	}
	var items []models.MonitorLog
	if err := query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	ok(c, paginated(items, total, page, size))
}

func (s *Server) listNotificationLogs(c *gin.Context) {
	page, size := pageParams(c)
	query := s.db.Model(&models.NotificationLog{})
	if event := strings.TrimSpace(c.Query("event")); event != "" {
		query = query.Where("event = ?", event)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if channel := strings.TrimSpace(c.Query("channel")); channel != "" {
		query = query.Where("channel_name LIKE ?", "%"+channel+"%")
	}
	if subject := strings.TrimSpace(c.Query("subject")); subject != "" {
		query = query.Where("subject LIKE ?", "%"+subject+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		serverError(c, err)
		return
	}
	var items []models.NotificationLog
	if err := query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	ok(c, paginated(items, total, page, size))
}
