package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestParseRDAP(t *testing.T) {
	body := []byte(`{
		"ldhName":"EXAMPLE.COM",
		"status":["client transfer prohibited"],
		"events":[
			{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
			{"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"}
		],
		"entities":[{"roles":["registrar"],"handle":"376","vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]}],
		"nameservers":[{"ldhName":"A.IANA-SERVERS.NET"}]
	}`)
	info, err := parseRDAP(body)
	if err != nil {
		t.Fatalf("parseRDAP error: %v", err)
	}
	if info.Registrar != "Example Registrar, Inc." {
		t.Fatalf("registrar = %q", info.Registrar)
	}
	if info.ExpiresAt == nil || info.ExpiresAt.Year() != 2027 {
		t.Fatalf("expires_at = %v", info.ExpiresAt)
	}
	if info.RegisteredAt == nil || info.RegisteredAt.Year() != 1995 {
		t.Fatalf("registered_at = %v", info.RegisteredAt)
	}
	if len(info.Nameservers) != 1 {
		t.Fatalf("nameservers = %v", info.Nameservers)
	}
}

func TestParseRDAPMissingExpiry(t *testing.T) {
	info, err := parseRDAP([]byte(`{"ldhName":"example.com","events":[],"entities":[{"roles":["registrar"],"handle":"R1"}]}`))
	if err == nil {
		t.Fatal("expected missing expiry error")
	}
	if info == nil || info.Registrar == "" {
		t.Fatal("expected partial registrar information")
	}
}

func TestParseWhois(t *testing.T) {
	text := `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
`
	info := parseWhois(text)
	if info == nil {
		t.Fatal("parseWhois returned nil")
	}
	if !strings.Contains(info.Registrar, "RESERVED") {
		t.Fatalf("registrar = %q", info.Registrar)
	}
	if info.ExpiresAt == nil || info.ExpiresAt.Year() != 2027 {
		t.Fatalf("expiry = %v", info.ExpiresAt)
	}
}

func TestParseWhoisReferralAndDates(t *testing.T) {
	referral := parseWhoisReferral("refer:        whois.verisign-grs.com\n")
	if referral != "whois.verisign-grs.com" {
		t.Fatalf("referral = %q", referral)
	}
	tests := map[string]int{
		"2027-08-13T04:00:00Z": 2027,
		"13-Aug-2027":          2027,
		"2027.08.13":           2027,
		"2027-08-13 04:00:00":  2027,
	}
	for raw, year := range tests {
		parsed, err := parseFlexibleTime(raw)
		if err != nil {
			t.Errorf("parseFlexibleTime(%q): %v", raw, err)
			continue
		}
		if parsed.Year() != year {
			t.Errorf("parseFlexibleTime(%q).Year() = %d", raw, parsed.Year())
		}
	}
}

func TestDomainStatus(t *testing.T) {
	now := time.Now()
	if got := domainStatus(-1, 30); got != "expired" {
		t.Fatalf("expired status = %s", got)
	}
	if got := domainStatus(0, 30); got != "expiring" {
		t.Fatalf("today status = %s", got)
	}
	if got := domainStatus(31, 30); got != "normal" {
		t.Fatalf("normal status = %s", got)
	}
	_ = now
}
