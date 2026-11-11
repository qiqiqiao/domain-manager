package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"domain-manager/internal/models"
	"domain-manager/internal/security"
)

type Message struct {
	Event    string
	Subject  string
	Title    string
	Markdown string
}

var (
	telegramTokenRE = regexp.MustCompile(`^[0-9]{5,}:[A-Za-z0-9_-]{20,}$`)
	telegramChatRE  = regexp.MustCompile(`^(?:-?[0-9]{3,}|@[A-Za-z0-9_]{4,})$`)
)

type ChannelConfig struct {
	BotToken   string `json:"bot_token,omitempty"`
	ChatID     string `json:"chat_id,omitempty"`
	ThreadID   string `json:"thread_id,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
	Secret     string `json:"secret,omitempty"`
	UseCard    bool   `json:"use_card,omitempty"`
}

func ParseConfig(raw string) (ChannelConfig, error) {
	var cfg ChannelConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, errors.New("通知渠道配置格式无效")
	}
	return cfg, nil
}

func ValidateConfig(channelType string, cfg ChannelConfig, allowPrivate bool) error {
	switch channelType {
	case models.ChannelTelegram:
		if strings.TrimSpace(cfg.BotToken) == "" || strings.TrimSpace(cfg.ChatID) == "" {
			return errors.New("Telegram Bot Token 与 Chat ID 不能为空")
		}
		if !telegramTokenRE.MatchString(strings.TrimSpace(cfg.BotToken)) {
			return errors.New("Telegram Bot Token 格式无效")
		}
		if !telegramChatRE.MatchString(strings.TrimSpace(cfg.ChatID)) {
			return errors.New("Telegram Chat ID 格式无效")
		}
		if cfg.ThreadID != "" {
			if _, err := strconv.Atoi(cfg.ThreadID); err != nil {
				return errors.New("Telegram Topic ID 必须为数字")
			}
		}
	case models.ChannelLark, models.ChannelFeishu:
		if strings.TrimSpace(cfg.WebhookURL) == "" {
			return errors.New("Webhook URL 不能为空")
		}
		if _, err := security.ValidateWebhookURL(cfg.WebhookURL, allowPrivate); err != nil {
			return err
		}
	case models.ChannelDingTalk:
		if strings.TrimSpace(cfg.WebhookURL) == "" {
			return errors.New("钉钉 Webhook URL 不能为空")
		}
		if _, err := security.ValidateWebhookURL(cfg.WebhookURL, allowPrivate); err != nil {
			return err
		}
	default:
		return errors.New("不支持的通知渠道类型")
	}
	return nil
}

func MaskConfig(channelType, rawConfig string) map[string]any {
	cfg, err := ParseConfig(rawConfig)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	switch channelType {
	case models.ChannelTelegram:
		out["bot_token"] = security.MaskSecret(cfg.BotToken)
		out["chat_id"] = cfg.ChatID
		if cfg.ThreadID != "" {
			out["thread_id"] = cfg.ThreadID
		}
	case models.ChannelLark, models.ChannelFeishu:
		out["webhook_url"] = security.MaskURL(cfg.WebhookURL)
		out["use_card"] = cfg.UseCard
		if cfg.Secret != "" {
			out["secret"] = "••••••••"
			out["has_secret"] = true
		}
	case models.ChannelDingTalk:
		out["webhook_url"] = security.MaskURL(cfg.WebhookURL)
		if cfg.Secret != "" {
			out["secret"] = "••••••••"
			out["has_secret"] = true
		}
	}
	return out
}

// MergeMasked updates only changed values; placeholder values preserve the
// encrypted secret on the server so it is never sent back to the browser.
func MergeMasked(existingRaw string, incoming ChannelConfig) ChannelConfig {
	existing, err := ParseConfig(existingRaw)
	if err != nil {
		return incoming
	}
	if security.IsMasked(incoming.BotToken) {
		incoming.BotToken = existing.BotToken
	}
	if security.IsMasked(incoming.WebhookURL) {
		incoming.WebhookURL = existing.WebhookURL
	}
	if security.IsMasked(incoming.Secret) {
		incoming.Secret = existing.Secret
	}
	if incoming.ChatID == "" {
		incoming.ChatID = existing.ChatID
	}
	if incoming.ThreadID == "" {
		incoming.ThreadID = existing.ThreadID
	}
	return incoming
}

type sender struct {
	settings interface{ Bool(string) bool }
	client   *http.Client
}

func NewSender(settings interface{ Bool(string) bool }) *sender {
	return &sender{settings: settings, client: &http.Client{Timeout: 20 * time.Second}}
}

func (s *sender) Send(ctx context.Context, channelType string, cfg ChannelConfig, msg Message) error {
	if s.settings != nil {
		allowPrivate := s.settings.Bool("allow_private_targets")
		switch channelType {
		case models.ChannelLark, models.ChannelFeishu, models.ChannelDingTalk:
			if _, err := security.ValidateWebhookURL(cfg.WebhookURL, allowPrivate); err != nil {
				return err
			}
		}
	}
	client := security.NewSafeHTTPClient(false, 20*time.Second)
	if s.settings != nil {
		client = security.NewSafeHTTPClient(s.settings.Bool("allow_private_targets"), 20*time.Second)
	}
	switch channelType {
	case models.ChannelTelegram:
		return sendTelegram(ctx, client, cfg, msg)
	case models.ChannelLark, models.ChannelFeishu:
		return sendFeishu(ctx, client, cfg, msg)
	case models.ChannelDingTalk:
		return sendDingTalk(ctx, client, cfg, msg)
	default:
		return errors.New("不支持的通知渠道类型")
	}
}

func sendTelegram(ctx context.Context, client *http.Client, cfg ChannelConfig, msg Message) error {
	endpoint := "https://api.telegram.org/bot" + url.PathEscape(cfg.BotToken) + "/sendMessage"
	title := security.TruncateRunes(msg.Title, 200)
	for _, chunk := range splitTelegramText(msg.Markdown, 3800) {
		text := "<b>" + html.EscapeString(title) + "</b>\n\n" + html.EscapeString(chunk)
		body := map[string]any{
			"chat_id": cfg.ChatID, "text": text, "parse_mode": "HTML",
			"disable_web_page_preview": true,
		}
		if cfg.ThreadID != "" {
			if n, err := strconv.Atoi(cfg.ThreadID); err == nil {
				body["message_thread_id"] = n
			}
		}
		respBody, status, err := postJSON(ctx, client, endpoint, body, nil)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("Telegram API 返回 HTTP %d: %s", status, trimBody(respBody))
		}
		var result struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return errors.New("Telegram 返回内容无法解析")
		}
		if !result.OK {
			return fmt.Errorf("Telegram 发送失败: %s", result.Description)
		}
	}
	return nil
}

// splitTelegramText keeps each Telegram message below its 4096-character
// limit. Splitting the raw markdown before HTML escaping prevents broken tags
// or entities at chunk boundaries.
func splitTelegramText(text string, max int) []string {
	if max <= 0 {
		max = 3800
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return []string{""}
	}
	var chunks []string
	for len(runes) > max {
		chunks = append(chunks, string(runes[:max]))
		runes = runes[max:]
	}
	chunks = append(chunks, string(runes))
	return chunks
}

func sendFeishu(ctx context.Context, client *http.Client, cfg ChannelConfig, msg Message) error {
	payload := map[string]any{}
	if cfg.UseCard {
		payload = map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"config": map[string]any{"wide_screen_mode": true},
				"header": map[string]any{
					"template": "blue",
					"title":    map[string]any{"tag": "plain_text", "content": msg.Title},
				},
				"elements": []any{
					map[string]any{"tag": "markdown", "content": msg.Markdown},
				},
			},
		}
	} else {
		payload = map[string]any{
			"msg_type": "text",
			"content":  map[string]any{"text": msg.Title + "\n\n" + msg.Markdown},
		}
	}
	if cfg.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		stringToSign := ts + "\n" + cfg.Secret
		mac := hmac.New(sha256.New, []byte(stringToSign))
		payload["timestamp"] = ts
		payload["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	respBody, status, err := postJSON(ctx, client, cfg.WebhookURL, payload, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("飞书/Lark Webhook 返回 HTTP %d: %s", status, trimBody(respBody))
	}
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil // some Lark deployments return an empty successful response
	}
	if result.Code != 0 {
		return fmt.Errorf("飞书/Lark 发送失败: %s (code=%d)", result.Msg, result.Code)
	}
	return nil
}

func sendDingTalk(ctx context.Context, client *http.Client, cfg ChannelConfig, msg Message) error {
	endpoint, err := url.Parse(cfg.WebhookURL)
	if err != nil {
		return errors.New("钉钉 Webhook URL 无效")
	}
	if cfg.Secret != "" {
		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
		stringToSign := ts + "\n" + cfg.Secret
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write([]byte(stringToSign))
		sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		q := endpoint.Query()
		q.Set("timestamp", ts)
		q.Set("sign", sign)
		endpoint.RawQuery = q.Encode()
	}
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": msg.Title,
			"text":  "### " + msg.Title + "\n\n" + msg.Markdown,
		},
	}
	respBody, status, err := postJSON(ctx, client, endpoint.String(), payload, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("钉钉 Webhook 返回 HTTP %d: %s", status, trimBody(respBody))
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return errors.New("钉钉返回内容无法解析")
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("钉钉发送失败: %s (errcode=%d)", result.ErrMsg, result.ErrCode)
	}
	return nil
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, payload any, headers map[string]string) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, errors.New("通知请求地址无效")
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "domain-manager/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("网络请求失败: %w", stripURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// stripURLError removes the request URL from net/http errors. URLs for
// Telegram and webhook providers contain credentials in the path/query and must
// never reach notification logs.
func stripURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func trimBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	return security.TruncateRunes(s, 300)
}
