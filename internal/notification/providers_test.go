package notification

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskConfigDoesNotLeakSecrets(t *testing.T) {
	cfg, _ := json.Marshal(ChannelConfig{BotToken: "123456:ABCDEFGHIJKLMNOP", ChatID: "-100123"})
	masked := MaskConfig("telegram", string(cfg))
	raw, _ := json.Marshal(masked)
	if strings.Contains(string(raw), "ABCDEFGHIJKLMNOP") {
		t.Fatalf("bot token leaked: %s", raw)
	}
	if masked["chat_id"] != "-100123" {
		t.Fatalf("chat id missing: %v", masked)
	}
}

func TestMergeMaskedPreservesSecrets(t *testing.T) {
	existing, _ := json.Marshal(ChannelConfig{
		WebhookURL: "https://open.feishu.cn/open-apis/bot/v2/hook/secret-token",
		Secret:     "signing-secret", UseCard: true,
	})
	incoming := ChannelConfig{WebhookURL: "https://open.feishu.cn/••••••••", Secret: "••••••••"}
	merged := MergeMasked(string(existing), incoming)
	if merged.WebhookURL != "https://open.feishu.cn/open-apis/bot/v2/hook/secret-token" {
		t.Fatalf("webhook not preserved: %q", merged.WebhookURL)
	}
	if merged.Secret != "signing-secret" {
		t.Fatalf("secret not preserved: %q", merged.Secret)
	}
}

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig("telegram", ChannelConfig{BotToken: "12345:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatID: "-100123"}, true); err != nil {
		t.Fatalf("valid telegram config rejected: %v", err)
	}
	if err := ValidateConfig("telegram", ChannelConfig{BotToken: "bad", ChatID: "1"}, false); err == nil {
		t.Fatal("invalid bot token accepted")
	}
	if err := ValidateConfig("feishu", ChannelConfig{WebhookURL: "http://example.com/hook"}, true); err == nil {
		t.Fatal("http webhook accepted")
	}
	if err := ValidateConfig("dingtalk", ChannelConfig{WebhookURL: "https://example.com/hook"}, true); err != nil {
		t.Fatalf("valid webhook rejected: %v", err)
	}
}
