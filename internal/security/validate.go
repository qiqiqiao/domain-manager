package security

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"

func RandomPassword(length int) (string, error) {
	if length < 12 {
		length = 12
	}
	var b strings.Builder
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[n.Int64()])
	}
	return b.String(), nil
}

func RandomToken(bytesLen int) (string, error) {
	if bytesLen < 16 {
		bytesLen = 32
	}
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("密码至少需要 8 个字符")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func ConstantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var hostLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain validates and canonicalizes a hostname. It optionally allows
// a single leading wildcard label (used only by ACME certificate orders).
func NormalizeDomain(input string, allowWildcard bool) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return "", errors.New("域名不能为空")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", errors.New("域名格式无效")
		}
		s = u.Hostname()
	}
	s = strings.TrimSuffix(s, ".")
	if strings.ContainsAny(s, "/\\@ \t\r\n") {
		return "", errors.New("域名格式无效")
	}
	if ip := net.ParseIP(s); ip != nil {
		return "", errors.New("不支持直接监控 IP 地址")
	}
	wildcard := false
	if strings.HasPrefix(s, "*.") {
		if !allowWildcard {
			return "", errors.New("该场景不允许通配符域名")
		}
		wildcard = true
		s = strings.TrimPrefix(s, "*.")
		if strings.Contains(s, "*") {
			return "", errors.New("通配符只能出现在最左侧")
		}
	}
	if strings.Contains(s, "*") {
		return "", errors.New("域名中不允许使用通配符")
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("国际化域名转换失败: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(ascii) > 253 {
		return "", errors.New("域名长度超过限制")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("域名必须包含至少一个点")
	}
	for _, label := range labels {
		if !hostLabelRE.MatchString(label) {
			return "", fmt.Errorf("域名标签无效: %s", label)
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 && !strings.HasPrefix(tld, "xn--") {
		return "", errors.New("顶级域名无效")
	}
	if _, ok := publicsuffix.PublicSuffix(ascii); !ok {
		return "", errors.New("无法识别域名后缀")
	}
	if wildcard {
		return "*." + ascii, nil
	}
	return ascii, nil
}

// RegistrableDomain returns the eTLD+1, used to derive a DNS zone.
func RegistrableDomain(domain string) string {
	domain = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(domain), "."), "*.")
	base, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return base
}

// ValidateWebhookURL enforces HTTPS, no embedded credentials, and a publicly
// routable destination. It is a first line of defence; SafeDialer checks the
// actual connected IP again to mitigate DNS rebinding.
func ValidateWebhookURL(raw string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("Webhook URL 格式无效")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, errors.New("Webhook URL 必须使用 HTTPS")
	}
	if u.User != nil {
		return nil, errors.New("Webhook URL 不允许包含用户名密码")
	}
	if u.Hostname() == "" {
		return nil, errors.New("Webhook URL 缺少主机名")
	}
	port := u.Port()
	if port != "" && port != "443" && port != "8443" {
		return nil, errors.New("Webhook 端口仅允许 443 或 8443")
	}
	if allowPrivate {
		return u, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, errors.New("Webhook 主机名无法解析")
	}
	for _, ip := range ips {
		if !IsPublicIP(ip) {
			return nil, errors.New("Webhook URL 指向内网或保留地址，已拒绝")
		}
	}
	return u, nil
}

func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !ip.IsGlobalUnicast() {
		return false
	}
	blocked := []string{
		"100.64.0.0/10", "0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "fec0::/10", "2001:db8::/32",
		// NAT64 well-known prefix and local-use prefix can embed private IPv4
		// destinations, so treat them as non-public.
		"64:ff9b::/96", "64:ff9b:1::/48",
	}
	for _, cidr := range blocked {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return false
		}
	}
	return true
}

func MaskSecret(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 6 {
		return "••••••••"
	}
	return value[:2] + "••••••••" + value[len(value)-2:]
}

func IsMasked(value string) bool {
	return strings.Contains(value, "••")
}

// MaskURL keeps the origin visible while hiding the secret path/query.
func MaskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return MaskSecret(raw)
	}
	return u.Scheme + "://" + u.Host + "/••••••••"
}

func SanitizeText(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return TruncateRunes(strings.TrimSpace(b.String()), maxLen)
}

// TruncateRunes limits a string by Unicode code points. Byte slicing can split
// a multi-byte Chinese character and produce invalid UTF-8.
func TruncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}

// TruncateTailRunes keeps the last maxRunes code points of s.
func TruncateTailRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[len(runes)-maxRunes:])
}

func DaysUntil(t time.Time) int {
	return DaysUntilIn(t, time.Local)
}

// DaysUntilIn counts calendar days in loc. Using UTC midnights avoids the
// 23/25-hour days around daylight-saving transitions.
func DaysUntilIn(t time.Time, loc *time.Location) int {
	if loc == nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	local := t.In(loc)
	target := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return int(target.Sub(today) / (24 * time.Hour))
}
