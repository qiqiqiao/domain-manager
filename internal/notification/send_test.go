package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestSendTelegramRequest(t *testing.T) {
	var captured *http.Request
	var payload map[string]any
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		captured = req
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &payload)
		return jsonResponse(200, `{"ok":true}`), nil
	})}
	err := sendTelegram(context.Background(), client, ChannelConfig{BotToken: "123:abc", ChatID: "-100"}, Message{
		Title: "Test", Markdown: "hello <world>",
	})
	if err != nil {
		t.Fatalf("send telegram: %v", err)
	}
	if captured == nil || !strings.Contains(captured.URL.Path, "/bot123:abc/sendMessage") {
		t.Fatalf("unexpected request URL: %v", captured)
	}
	if payload["chat_id"] != "-100" || payload["parse_mode"] != "HTML" {
		t.Fatalf("unexpected payload: %v", payload)
	}
	if strings.Contains(payload["text"].(string), "<world>") {
		t.Fatal("message text was not HTML-escaped")
	}
}

func TestSendFeishuCardAndSignature(t *testing.T) {
	var payload map[string]any
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &payload)
		return jsonResponse(200, `{"code":0,"msg":"success"}`), nil
	})}
	err := sendFeishu(context.Background(), client, ChannelConfig{
		WebhookURL: "https://open.feishu.cn/open-apis/bot/v2/hook/test", Secret: "secret", UseCard: true,
	}, Message{Title: "SSL 告警", Markdown: "domain: example.com"})
	if err != nil {
		t.Fatalf("send feishu: %v", err)
	}
	if payload["msg_type"] != "interactive" {
		t.Fatalf("msg_type = %v", payload["msg_type"])
	}
	if payload["sign"] == "" || payload["timestamp"] == "" {
		t.Fatal("signature fields missing")
	}
	card, ok := payload["card"].(map[string]any)
	if !ok {
		t.Fatal("card missing")
	}
	if _, ok := card["header"]; !ok {
		t.Fatal("card header missing")
	}
}

func TestSendDingTalkSignatureAndMarkdown(t *testing.T) {
	var captured *http.Request
	var payload map[string]any
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		captured = req
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &payload)
		return jsonResponse(200, `{"errcode":0,"errmsg":"ok"}`), nil
	})}
	err := sendDingTalk(context.Background(), client, ChannelConfig{
		WebhookURL: "https://oapi.dingtalk.com/robot/send?access_token=test", Secret: "secret",
	}, Message{Title: "证书到期", Markdown: "hello"})
	if err != nil {
		t.Fatalf("send dingtalk: %v", err)
	}
	if captured.URL.Query().Get("sign") == "" || captured.URL.Query().Get("timestamp") == "" {
		t.Fatal("dingtalk signature query missing")
	}
	if payload["msgtype"] != "markdown" {
		t.Fatalf("msgtype = %v", payload["msgtype"])
	}
}

func TestProviderErrorResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(200, `{"errmsg":"invalid sign","errcode":310000}`), nil
	})}
	err := sendDingTalk(context.Background(), client, ChannelConfig{
		WebhookURL: "https://oapi.dingtalk.com/robot/send?access_token=test",
	}, Message{Title: "x", Markdown: "y"})
	if err == nil || !strings.Contains(err.Error(), "310000") {
		t.Fatalf("expected provider error, got %v", err)
	}
}
