package security

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 test secret for SHA-1: "12345678901234567890".
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		got, err := GenerateTOTPCode(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("unix %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Fatalf("unix %d code = %s, want %s", tc.unix, got, tc.want)
		}
		if step, ok := VerifyTOTP(secret, got, time.Unix(tc.unix, 0), 1); !ok {
			t.Fatalf("unix %d code %s was not accepted", tc.unix, got)
		} else if step != tc.unix/TOTPPeriod {
			t.Fatalf("unix %d step = %d", tc.unix, step)
		}
	}
}

func TestTOTPWindowAndFormat(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	code, err := GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(30*time.Second), 1); !ok {
		t.Fatal("previous step should be accepted within the window")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(2*time.Minute), 1); ok {
		t.Fatal("code outside the window was accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 1); ok {
		t.Fatal("short code was accepted")
	}
	if _, ok := VerifyTOTP(secret, "abcdef", now, 1); ok {
		t.Fatal("non-numeric code was accepted")
	}
}

func TestRecoveryCodesAreSaltedHashes(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 5 || len(hashes) != 5 {
		t.Fatalf("got %d plain and %d hashes", len(plain), len(hashes))
	}
	for i, code := range plain {
		if strings.Contains(hashes[i], code) {
			t.Fatal("hash must not contain the plaintext code")
		}
		if !RecoveryCodeMatches(hashes[i], code) {
			t.Fatalf("recovery code %d did not match", i)
		}
		if !RecoveryCodeMatches(hashes[i], strings.ToLower(strings.ReplaceAll(code, "-", " "))) {
			t.Fatalf("normalized recovery code %d did not match", i)
		}
		if RecoveryCodeMatches(hashes[i], "wrong-code") {
			t.Fatal("wrong recovery code matched")
		}
	}
}
