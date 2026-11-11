package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	TOTPSecretBytes = 20
	TOTPDigits      = 6
	TOTPPeriod      = 30
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new RFC 4648 base32 secret without padding.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(buf), nil
}

// TOTPURL builds the standard otpauth:// URI used by authenticator apps.
func TOTPURL(issuer, account, secret string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "Domain Manager"
	}
	label := url.PathEscape(issuer + ":" + account)
	values := url.Values{}
	values.Set("secret", normalizeTOTPSecret(secret))
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	values.Set("period", fmt.Sprintf("%d", TOTPPeriod))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func normalizeTOTPSecret(secret string) string {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")
	return secret
}

// GenerateTOTPCode returns the six-digit code for the given instant.
func GenerateTOTPCode(secret string, at time.Time) (string, error) {
	return hotpCode(secret, uint64(at.Unix()/TOTPPeriod))
}

// VerifyTOTP checks a six-digit code with a +/- window of time steps. It
// returns the matched time step so callers can reject replayed codes.
func VerifyTOTP(secret, code string, at time.Time, window int) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != TOTPDigits {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	if window < 0 {
		window = 0
	}
	counter := int64(at.Unix() / TOTPPeriod)
	for offset := -window; offset <= window; offset++ {
		step := counter + int64(offset)
		if step < 0 {
			continue
		}
		expected, err := hotpCode(secret, uint64(step))
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func hotpCode(secret string, counter uint64) (string, error) {
	key, err := totpEncoding.DecodeString(normalizeTOTPSecret(secret))
	if err != nil || len(key) == 0 {
		return "", errors.New("TOTP 密钥格式无效")
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000), nil
}

// GenerateRecoveryCodes creates human-readable one-time codes and the SHA-256
// hashes that should be persisted.
func GenerateRecoveryCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		return nil, nil, errors.New("恢复码数量无效")
	}
	plain := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		raw := totpEncoding.EncodeToString(buf)
		code := raw[:4] + "-" + raw[4:8] + "-" + raw[8:]
		plain = append(plain, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return plain, hashes, nil
}

// HashRecoveryCode normalizes a recovery code before hashing so users can omit
// separators or use lowercase.
func HashRecoveryCode(code string) string {
	normalized := normalizeRecoveryCode(code)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// RecoveryCodeMatches compares a submitted code with a stored SHA-256 hash in
// constant time.
func RecoveryCodeMatches(hash, code string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(HashRecoveryCode(code))) == 1
}

func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	for _, sep := range []string{"-", " ", "\t", "\n", "\r"} {
		code = strings.ReplaceAll(code, sep, "")
	}
	return code
}
