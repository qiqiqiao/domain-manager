package dns

import (
	"testing"
)

func TestAliPercent(t *testing.T) {
	got := aliPercent("a b*~/_-.&=")
	want := "a%20b%2A~%2F_-.%26%3D"
	if got != want {
		t.Fatalf("aliPercent = %q, want %q", got, want)
	}
}

func TestRegistrable(t *testing.T) {
	tests := map[string]string{
		"www.example.com":    "example.com",
		"a.b.example.co.uk":  "example.co.uk",
		"*.example.com":      "example.com",
		"example.com.cn":     "example.com.cn",
		"sub.example.com.cn": "example.com.cn",
	}
	for input, want := range tests {
		if got := registrable(input); got != want {
			t.Errorf("registrable(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseAndValidateProviderConfig(t *testing.T) {
	cfg, err := ParseConfig(`{"api_token":"token","zone":"example.com"}`)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := Validate("cloudflare", cfg); err != nil {
		t.Fatalf("validate cloudflare: %v", err)
	}
	if err := Validate("dnspod", cfg); err == nil {
		t.Fatal("missing DNSPod credentials should fail")
	}
	if _, err := ParseConfig(`not-json`); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
