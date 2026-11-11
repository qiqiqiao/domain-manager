package security

import (
	"net"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input   string
		wild    bool
		want    string
		wantErr bool
	}{
		{"Example.COM", false, "example.com", false},
		{"https://www.example.com/path?q=1", false, "www.example.com", false},
		{"example.com.", false, "example.com", false},
		{"*.example.com", true, "*.example.com", false},
		{"*.example.com", false, "", true},
		{"exa mple.com", false, "", true},
		{"127.0.0.1", false, "", true},
		{"localhost", false, "", true},
		{"-bad.example.com", false, "", true},
		{"example", false, "", true},
		{"foo.*.example.com", true, "", true},
	}
	for _, tc := range tests {
		got, err := NormalizeDomain(tc.input, tc.wild)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeDomain(%q) expected error, got %q", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
	}
	for _, tc := range tests {
		if got := IsPublicIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestMaskSecretAndURL(t *testing.T) {
	secret := MaskSecret("123456:ABCDEFGHIJK")
	if secret == "123456:ABCDEFGHIJK" || !IsMasked(secret) {
		t.Fatalf("secret was not masked: %q", secret)
	}
	url := MaskURL("https://open.feishu.cn/open-apis/bot/v2/hook/very-secret-token")
	if IsMasked(url) == false || url == "" {
		t.Fatalf("URL was not masked: %q", url)
	}
}

func TestDaysUntilLocalDates(t *testing.T) {
	target := time.Now().In(time.Local).AddDate(0, 0, 7)
	if got := DaysUntil(target); got != 7 {
		t.Fatalf("DaysUntil(+7d) = %d", got)
	}
	past := time.Now().AddDate(0, 0, -2)
	if got := DaysUntil(past); got != -2 {
		t.Fatalf("DaysUntil(-2d) = %d", got)
	}
}
