package api

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"domain-manager/internal/models"
	"domain-manager/internal/notification"

	"github.com/gin-gonic/gin"
)

type channelRequest struct {
	Name    string                     `json:"name"`
	Type    string                     `json:"type"`
	Enabled *bool                      `json:"enabled"`
	Config  notification.ChannelConfig `json:"config"`
}

func (s *Server) channelView(channel *models.NotificationChannel) gin.H {
	return gin.H{
		"id": channel.ID, "name": channel.Name, "type": channel.Type,
		"enabled": channel.Enabled, "config": s.notifier.MaskedConfig(channel),
		"last_test_at": channel.LastTestAt, "last_test_ok": channel.LastTestOK,
		"last_error": channel.LastError, "created_at": channel.CreatedAt, "updated_at": channel.UpdatedAt,
	}
}

func (s *Server) listNotifications(c *gin.Context) {
	var channels []models.NotificationChannel
	if err := s.db.Order("id DESC").Find(&channels).Error; err != nil {
		serverError(c, err)
		return
	}
	items := make([]gin.H, 0, len(channels))
	for i := range channels {
		items = append(items, s.channelView(&channels[i]))
	}
	ok(c, items)
}

func (s *Server) createNotification(c *gin.Context) {
	var req channelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "通知渠道参数无效")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Name == "" || len(req.Name) > 100 {
		badRequest(c, "渠道名称不能为空且不能超过 100 个字符")
		return
	}
	if req.Type != models.ChannelTelegram && req.Type != models.ChannelLark && req.Type != models.ChannelFeishu && req.Type != models.ChannelDingTalk {
		badRequest(c, "不支持的通知渠道类型")
		return
	}
	if err := s.notifier.ValidateChannel(req.Type, req.Config); err != nil {
		badRequest(c, err.Error())
		return
	}
	encrypted, err := s.notifier.EncryptConfig(req.Config)
	if err != nil {
		serverError(c, err)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	channel := models.NotificationChannel{Name: req.Name, Type: req.Type, ConfigEncrypted: encrypted, Enabled: enabled}
	if err := s.db.Create(&channel).Error; err != nil {
		serverError(c, err)
		return
	}
	created(c, s.channelView(&channel))
}

func (s *Server) updateNotification(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var channel models.NotificationChannel
	if err := s.db.First(&channel, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "通知渠道不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	var req channelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "通知渠道参数无效")
		return
	}
	existing, err := s.notifier.DecryptConfig(channel.ConfigEncrypted)
	if err != nil {
		serverError(c, err)
		return
	}
	config := notification.MergeMasked(mustJSON(existing), req.Config)
	if req.Type == "" {
		req.Type = channel.Type
	}
	if err := s.notifier.ValidateChannel(req.Type, config); err != nil {
		badRequest(c, err.Error())
		return
	}
	encrypted, err := s.notifier.EncryptConfig(config)
	if err != nil {
		serverError(c, err)
		return
	}
	updates := map[string]any{"config_encrypted": encrypted, "type": req.Type}
	if strings.TrimSpace(req.Name) != "" {
		if len(req.Name) > 100 {
			badRequest(c, "渠道名称不能超过 100 个字符")
			return
		}
		updates["name"] = strings.TrimSpace(req.Name)
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if err := s.db.Model(&channel).Updates(updates).Error; err != nil {
		serverError(c, err)
		return
	}
	_ = s.db.First(&channel, id).Error
	ok(c, s.channelView(&channel))
}

func mustJSON(cfg notification.ChannelConfig) string {
	data, _ := json.Marshal(cfg)
	return string(data)
}

func (s *Server) deleteNotification(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var channel models.NotificationChannel
	if err := s.db.First(&channel, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "通知渠道不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	if err := s.db.Delete(&channel).Error; err != nil {
		serverError(c, err)
		return
	}
	s.notifier.RemoveChannelFromRules(id)
	ok(c, gin.H{"deleted": true})
}

func (s *Server) testNotification(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var channel models.NotificationChannel
	if err := s.db.First(&channel, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "通知渠道不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	if err := s.notifier.TestChannel(ctx, &channel); err != nil {
		ok(c, gin.H{"success": false, "error": err.Error()})
		return
	}
	ok(c, gin.H{"success": true})
}

func (s *Server) listRules(c *gin.Context) {
	rules, err := s.notifier.Rules()
	if err != nil {
		serverError(c, err)
		return
	}
	items := make([]gin.H, 0, len(rules))
	for i := range rules {
		var ids []uint
		_ = json.Unmarshal([]byte(rules[i].ChannelIDs), &ids)
		if ids == nil {
			ids = []uint{}
		}
		items = append(items, gin.H{
			"id": rules[i].ID, "event": rules[i].Event, "channel_ids": ids,
			"enabled": rules[i].Enabled, "dedup_hours": rules[i].DedupHours,
			"description": rules[i].Description,
		})
	}
	ok(c, items)
}

func (s *Server) updateRules(c *gin.Context) {
	var req struct {
		Rules []struct {
			Event      string `json:"event"`
			ChannelIDs []uint `json:"channel_ids"`
			Enabled    bool   `json:"enabled"`
			DedupHours int    `json:"dedup_hours"`
		} `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "告警规则参数无效")
		return
	}
	rules := make([]models.NotificationRule, 0, len(req.Rules))
	for _, item := range req.Rules {
		if item.DedupHours < 0 || item.DedupHours > 8760 {
			badRequest(c, "去重时间必须在 0-8760 小时之间")
			return
		}
		data, _ := json.Marshal(item.ChannelIDs)
		rules = append(rules, models.NotificationRule{
			Event: item.Event, ChannelIDs: string(data), Enabled: item.Enabled, DedupHours: item.DedupHours,
		})
	}
	if err := s.notifier.UpdateRules(rules); err != nil {
		badRequest(c, err.Error())
		return
	}
	s.listRules(c)
}
