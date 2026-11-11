package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"net/http"
)

type DomainInfo struct {
	Registrar    string
	RegisteredAt *time.Time
	ExpiresAt    *time.Time
	Source       string
	Statuses     []string
	Nameservers  []string
}

type rdapBootstrap struct {
	mu       sync.Mutex
	services map[string][]string
	fetched  time.Time
}

var fallbackRDAP = map[string][]string{
	"com": {"https://rdap.verisign.com/com/v1/"},
	"net": {"https://rdap.verisign.com/net/v1/"},
	"org": {"https://rdap.publicinterestregistry.org/rdap/"},
	"io":  {"https://rdap.identitydigital.services/rdap/"},
	"dev": {"https://www.registry.google/rdap/"},
	"app": {"https://www.registry.google/rdap/"},
	"xyz": {"https://rdap.centralnic.com/xyz/"},
	"top": {"https://rdap.zdnsgtld.com/top/"},
	"vip": {"https://rdap.zdnsgtld.com/vip/"},
	"cc":  {"https://ccwhois.verisign.com/rdap/"},
	"cn":  {"https://rdap.cnnic.cn/rdap/"},
}

type DomainLookup struct {
	settings *settings.Manager
	boot     rdapBootstrap
}

func NewDomainLookup(st *settings.Manager) *DomainLookup {
	return &DomainLookup{settings: st}
}

func (l *DomainLookup) Lookup(ctx context.Context, domain string) (*DomainInfo, error) {
	timeout := l.settings.Duration("rdap_timeout_seconds", 15*time.Second)
	allowPrivate := l.settings.Bool("allow_private_targets")
	client := security.NewSafeHTTPClient(allowPrivate, timeout)
	info, rdapErr := l.lookupRDAP(ctx, client, domain)
	if info != nil && info.ExpiresAt != nil {
		return info, nil
	}
	if !l.settings.Bool("whois_enabled") {
		if rdapErr == nil {
			rdapErr = errors.New("RDAP 未返回到期时间")
		}
		return info, fmt.Errorf("RDAP 查询失败: %w", rdapErr)
	}
	whoisInfo, whoisErr := l.lookupWHOIS(ctx, domain, allowPrivate, timeout)
	if whoisInfo != nil && (whoisInfo.ExpiresAt != nil || whoisInfo.Registrar != "") {
		if info != nil {
			mergeDomainInfo(whoisInfo, info)
		}
		if whoisInfo.ExpiresAt == nil {
			return whoisInfo, fmt.Errorf("RDAP/WHOIS 已返回注册信息，但未提供到期时间；WHOIS 错误: %v", whoisErr)
		}
		return whoisInfo, nil
	}
	if info != nil {
		return info, fmt.Errorf("RDAP 未提供到期时间，且 WHOIS 查询失败: %v", whoisErr)
	}
	return nil, fmt.Errorf("RDAP 查询失败: %v；WHOIS 查询失败: %v", rdapErr, whoisErr)
}

func mergeDomainInfo(dst, src *DomainInfo) {
	if dst.Registrar == "" {
		dst.Registrar = src.Registrar
	}
	if dst.RegisteredAt == nil {
		dst.RegisteredAt = src.RegisteredAt
	}
	if dst.ExpiresAt == nil {
		dst.ExpiresAt = src.ExpiresAt
	}
	dst.Statuses = append(dst.Statuses, src.Statuses...)
	dst.Nameservers = append(dst.Nameservers, src.Nameservers...)
}

func (l *DomainLookup) rdapServices(ctx context.Context, client *http.Client) map[string][]string {
	l.boot.mu.Lock()
	defer l.boot.mu.Unlock()
	if l.boot.services != nil && time.Since(l.boot.fetched) < 24*time.Hour {
		return l.boot.services
	}
	services := make(map[string][]string, len(fallbackRDAP))
	for k, v := range fallbackRDAP {
		services[k] = append([]string(nil), v...)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://data.iana.org/rdap/dns.json", nil)
	if err == nil {
		req.Header.Set("User-Agent", "domain-manager/1.0")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
				var data struct {
					Services [][][]any `json:"services"`
				}
				if json.Unmarshal(body, &data) == nil {
					for _, service := range data.Services {
						if len(service) < 2 {
							continue
						}
						tlds, urls := service[0], service[1]
						var urlList []string
						for _, u := range urls {
							if s, ok := u.(string); ok && strings.HasPrefix(s, "https://") {
								urlList = append(urlList, s)
							}
						}
						for _, t := range tlds {
							if s, ok := t.(string); ok && len(urlList) > 0 {
								services[strings.ToLower(s)] = append([]string(nil), urlList...)
							}
						}
					}
				}
			}
		}
	}
	l.boot.services = services
	l.boot.fetched = time.Now()
	return services
}

func (l *DomainLookup) lookupRDAP(ctx context.Context, client *http.Client, domain string) (*DomainInfo, error) {
	services := l.rdapServices(ctx, client)
	labels := strings.Split(domain, ".")
	var endpoints []string
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if urls, ok := services[suffix]; ok {
			endpoints = urls
			break
		}
	}
	if len(endpoints) == 0 {
		return nil, errors.New("该域名后缀暂无已知 RDAP 服务")
	}
	var lastErr error
	for _, base := range endpoints {
		base = strings.TrimRight(base, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/domain/"+domain, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		req.Header.Set("User-Agent", "domain-manager/1.0 (domain expiry monitor)")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, errors.New("RDAP 未找到该域名")
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = errors.New("RDAP 服务限流 (429)")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("RDAP 返回 HTTP %d", resp.StatusCode)
			continue
		}
		info, err := parseRDAP(body)
		if err != nil {
			lastErr = err
			continue
		}
		info.Source = "rdap"
		return info, nil
	}
	if lastErr == nil {
		lastErr = errors.New("RDAP 查询无结果")
	}
	return nil, lastErr
}

type rdapResponse struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

type rdapEntity struct {
	Handle     string       `json:"handle"`
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

func parseRDAP(body []byte) (*DomainInfo, error) {
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("解析 RDAP 响应失败: %w", err)
	}
	info := &DomainInfo{Statuses: r.Status}
	for _, event := range r.Events {
		t, err := parseFlexibleTime(event.Date)
		if err != nil {
			continue
		}
		switch strings.ToLower(event.Action) {
		case "registration":
			info.RegisteredAt = &t
		case "expiration":
			info.ExpiresAt = &t
		}
	}
	info.Registrar = findRegistrar(r.Entities)
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	if info.ExpiresAt == nil && info.Registrar == "" && len(info.Statuses) == 0 {
		return nil, errors.New("RDAP 响应中未包含可用注册信息")
	}
	if info.ExpiresAt == nil {
		return info, errors.New("RDAP 未返回到期时间")
	}
	return info, nil
}

func findRegistrar(entities []rdapEntity) string {
	for _, entity := range entities {
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrar") {
				if name := vcardName(entity.VCardArray); name != "" {
					return name
				}
				if entity.Handle != "" {
					return entity.Handle
				}
			}
		}
		if name := findRegistrar(entity.Entities); name != "" {
			return name
		}
	}
	return ""
}

func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		value, _ := prop[3].(string)
		if strings.EqualFold(name, "fn") && value != "" {
			return value
		}
	}
	return ""
}

func (l *DomainLookup) lookupWHOIS(ctx context.Context, domain string, allowPrivate bool, timeout time.Duration) (*DomainInfo, error) {
	first, err := whoisQuery(ctx, "whois.iana.org", domain, allowPrivate, timeout)
	if err != nil {
		return nil, err
	}
	referral := parseWhoisReferral(first)
	if referral == "" {
		if info := parseWhois(first); info != nil {
			info.Source = "whois"
			return info, nil
		}
		return nil, errors.New("WHOIS 未返回注册信息")
	}
	second, err := whoisQuery(ctx, referral, domain, allowPrivate, timeout)
	if err != nil {
		if info := parseWhois(first); info != nil {
			info.Source = "whois"
			return info, nil
		}
		return nil, fmt.Errorf("连接 WHOIS 服务器 %s 失败: %w", referral, err)
	}
	info := parseWhois(second)
	if info == nil {
		info = parseWhois(first)
	}
	if info == nil {
		return nil, fmt.Errorf("WHOIS 服务器 %s 返回内容中未找到可用字段", referral)
	}
	info.Source = "whois"
	return info, nil
}

func whoisQuery(ctx context.Context, server, query string, allowPrivate bool, timeout time.Duration) (string, error) {
	if strings.TrimSpace(server) == "" || strings.ContainsAny(server, "/ \t\r\n") {
		return "", errors.New("WHOIS 服务器地址无效")
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", server)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("解析 WHOIS 服务器失败: %w", err)
	}
	ordered := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			ordered = append(ordered, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			ordered = append(ordered, ip)
		}
	}
	var lastErr error
	attempts := 0
	for _, candidate := range ordered {
		if !allowPrivate && !security.IsPublicIP(candidate) {
			lastErr = errors.New("WHOIS 服务器解析到内网地址，已拒绝")
			continue
		}
		attempts++
		if attempts > 4 {
			break
		}
		deadline := time.Now().Add(timeout)
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(candidate.String(), "43"))
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(deadline)
		if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		reader := bufio.NewReader(io.LimitReader(conn, 2<<20))
		data, err := io.ReadAll(reader)
		conn.Close()
		if err != nil && len(data) == 0 {
			lastErr = err
			continue
		}
		return string(data), nil
	}
	if lastErr == nil {
		lastErr = errors.New("WHOIS 服务器没有可用地址")
	}
	return "", lastErr
}

func parseWhoisReferral(text string) string {
	re := regexp.MustCompile(`(?im)^\s*(?:refer|whois|referralserver|registrar whois server)\s*:\s*([a-z0-9.\-]+)\s*$`)
	m := re.FindStringSubmatch(text)
	if len(m) == 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

var whoisRegistrarRE = regexp.MustCompile(`(?im)^\s*(?:Registrar(?:\s+Name)?|Sponsoring Registrar|Registrar Organization|registrar)\s*:\s*(.+?)\s*$`)
var whoisCreatedRE = regexp.MustCompile(`(?im)^\s*(?:Creation Date|Created On|Created|Registration Time|Registered Date|Domain Registration Date|Registration Date)\s*:\s*(.+?)\s*$`)
var whoisExpiryRE = regexp.MustCompile(`(?im)^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|Expiration Time|paid-till|Renewal Date|到期时间)\s*:\s*(.+?)\s*$`)

func parseWhois(text string) *DomainInfo {
	info := &DomainInfo{}
	if m := whoisRegistrarRE.FindStringSubmatch(text); len(m) == 2 {
		info.Registrar = cleanWhoisValue(m[1])
	}
	if m := whoisCreatedRE.FindStringSubmatch(text); len(m) == 2 {
		if t, err := parseFlexibleTime(cleanWhoisValue(m[1])); err == nil {
			info.RegisteredAt = &t
		}
	}
	if m := whoisExpiryRE.FindStringSubmatch(text); len(m) == 2 {
		if t, err := parseFlexibleTime(cleanWhoisValue(m[1])); err == nil {
			info.ExpiresAt = &t
		}
	}
	if info.Registrar == "" && info.ExpiresAt == nil && info.RegisteredAt == nil {
		return nil
	}
	return info
}

func cleanWhoisValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimSpace(strings.SplitN(v, " #", 2)[0])
	v = strings.TrimSpace(strings.SplitN(v, "\t", 2)[0])
	return v
}

func parseFlexibleTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, " (UTC)")
	raw = strings.TrimSuffix(raw, " UTC")
	raw = strings.TrimPrefix(raw, "at ")
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, " ("); i > 0 {
		raw = raw[:i]
	}
	layouts := []string{
		time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z0700",
		"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02",
		"02-Jan-2006", "2006.01.02", "02.01.2006", "January 2 2006",
		time.RFC1123Z, time.RFC1123, "02-Jan-2006 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间: %s", raw)
}

// ParseRDAPForTest exposes parsing for unit tests.
func ParseRDAPForTest(body []byte) (*DomainInfo, error) { return parseRDAP(body) }

// ParseWhoisForTest exposes parsing for unit tests.
func ParseWhoisForTest(body string) *DomainInfo { return parseWhois(body) }
