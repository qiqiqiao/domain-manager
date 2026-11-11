package dns

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

type Config map[string]string

func ParseConfig(raw string) (Config, error) {
	if strings.TrimSpace(raw) == "" {
		return Config{}, nil
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, errors.New("DNS Provider 配置格式无效")
	}
	return cfg, nil
}

// Factory constructs a DNS-01 challenge provider from decrypted credentials.
type Factory func(Config) (challenge.Provider, error)

type providerEntry struct {
	validate func(Config) error
	factory  Factory
}

var (
	registryMu sync.RWMutex
	registry   = map[string]providerEntry{}
)

// RegisterProvider adds a DNS provider. The built-in providers register in
// init(); additional providers can call this from their own package init.
func RegisterProvider(name string, validate func(Config) error, factory Factory) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || factory == nil {
		return
	}
	registryMu.Lock()
	registry[name] = providerEntry{validate: validate, factory: factory}
	registryMu.Unlock()
}

func RegisteredProviders() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func Validate(name string, cfg Config) error {
	registryMu.RLock()
	entry, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	registryMu.RUnlock()
	if !ok {
		return errors.New("不支持的 DNS Provider")
	}
	if entry.validate != nil {
		return entry.validate(cfg)
	}
	return nil
}

func New(name string, cfg Config) (challenge.Provider, error) {
	if err := Validate(name, cfg); err != nil {
		return nil, err
	}
	registryMu.RLock()
	entry := registry[strings.ToLower(strings.TrimSpace(name))]
	registryMu.RUnlock()
	return entry.factory(cfg)
}

func init() {
	RegisterProvider("cloudflare", func(cfg Config) error {
		if strings.TrimSpace(cfg["api_token"]) == "" {
			return errors.New("Cloudflare API Token 不能为空")
		}
		return nil
	}, func(cfg Config) (challenge.Provider, error) { return newCloudflare(cfg), nil })
	RegisterProvider("dnspod", func(cfg Config) error {
		if strings.TrimSpace(cfg["secret_id"]) == "" || strings.TrimSpace(cfg["secret_key"]) == "" {
			return errors.New("DNSPod SecretId / SecretKey 不能为空")
		}
		return nil
	}, func(cfg Config) (challenge.Provider, error) { return newDNSPod(cfg), nil })
	RegisterProvider("alidns", func(cfg Config) error {
		if strings.TrimSpace(cfg["access_key_id"]) == "" || strings.TrimSpace(cfg["access_key_secret"]) == "" {
			return errors.New("阿里云 AccessKeyId / AccessKeySecret 不能为空")
		}
		return nil
	}, func(cfg Config) (challenge.Provider, error) { return newAliDNS(cfg), nil })
}

type base struct {
	records sync.Map // fqdn|value -> record id
}

func (b *base) key(fqdn, value string) string { return fqdn + "|" + value }
func (b *base) save(fqdn, value, id string)   { b.records.Store(b.key(fqdn, value), id) }
func (b *base) load(fqdn, value string) (string, bool) {
	v, ok := b.records.Load(b.key(fqdn, value))
	if !ok {
		return "", false
	}
	return v.(string), true
}
func (b *base) remove(fqdn, value string) { b.records.Delete(b.key(fqdn, value)) }

func challengeRecord(domain, keyAuth, zone string) (fqdn, value, sub, zoneName string, err error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn = strings.TrimSuffix(info.EffectiveFQDN, ".")
	value = info.Value
	zoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zoneName == "" {
		zoneName = registrable(domain)
	}
	if fqdn == zoneName {
		sub = "@"
	} else if strings.HasSuffix(fqdn, "."+zoneName) {
		sub = strings.TrimSuffix(fqdn, "."+zoneName)
	} else {
		return "", "", "", "", fmt.Errorf("验证记录 %s 不属于 DNS 区域 %s", fqdn, zoneName)
	}
	return fqdn, value, sub, zoneName, nil
}

func registrable(domain string) string {
	domain = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(domain), "."), "*.")
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Public suffix handling for common multi-label suffixes.
	secondLevel := map[string]bool{"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "co.uk": true, "org.uk": true, "com.au": true, "co.jp": true}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if secondLevel[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func waitForTXT(ctx context.Context, fqdn, value string, timeout time.Duration) error {
	target := strings.TrimSuffix(fqdn, ".") + "."
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, server := range resolvers {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 4 * time.Second}
					return d.DialContext(ctx, "udp", server)
				},
			}
			qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			txts, err := resolver.LookupTXT(qctx, target)
			cancel()
			if err != nil {
				continue
			}
			for _, txt := range txts {
				if strings.TrimSpace(txt) == value {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 DNS TXT 记录传播超时（%s）", fqdn)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// Cloudflare
type cloudflare struct {
	base
	token  string
	zoneID string
	zone   string
	client *http.Client
}

func newCloudflare(cfg Config) *cloudflare {
	return &cloudflare{token: cfg["api_token"], zoneID: cfg["zone_id"], zone: cfg["zone"], client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *cloudflare) Name() string { return "cloudflare" }

func (p *cloudflare) Timeout() (time.Duration, time.Duration) {
	return 120 * time.Second, 3 * time.Second
}

func (p *cloudflare) Present(domain, token, keyAuth string) error {
	fqdn, value, _, zoneName, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	zoneID := p.zoneID
	if zoneID == "" {
		var resp struct {
			Success bool `json:"success"`
			Result  []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := p.do(context.Background(), http.MethodGet, "/zones?name="+url.QueryEscape(zoneName), nil, &resp); err != nil {
			return err
		}
		if !resp.Success || len(resp.Result) == 0 {
			return fmt.Errorf("Cloudflare 未找到区域 %s，请检查 API Token 权限", zoneName)
		}
		zoneID = resp.Result[0].ID
	}
	payload := map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 60, "proxied": false}
	var created struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := p.do(context.Background(), http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, &created); err != nil {
		return err
	}
	if !created.Success || created.Result.ID == "" {
		return fmt.Errorf("Cloudflare 创建 TXT 记录失败")
	}
	p.save(fqdn, value, created.Result.ID)
	if err := waitForTXT(context.Background(), fqdn, value, 90*time.Second); err != nil {
		_ = p.CleanUp(domain, token, keyAuth)
		return err
	}
	return nil
}

func (p *cloudflare) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _, _, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	id, ok := p.load(fqdn, value)
	if !ok {
		return nil
	}
	zoneID := p.zoneID
	if zoneID == "" {
		_, _, _, zoneName, _ := challengeRecord(domain, keyAuth, p.zone)
		var resp struct {
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := p.do(context.Background(), http.MethodGet, "/zones?name="+url.QueryEscape(zoneName), nil, &resp); err != nil || len(resp.Result) == 0 {
			return err
		}
		zoneID = resp.Result[0].ID
	}
	var out struct {
		Success bool `json:"success"`
	}
	err = p.do(context.Background(), http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil, &out)
	if err == nil {
		p.remove(fqdn, value)
	}
	return err
}

func (p *cloudflare) do(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "domain-manager/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Cloudflare API 失败: %w", stripURLError(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare API 返回 HTTP %d: %s", resp.StatusCode, truncate(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析 Cloudflare 响应失败: %w", err)
		}
	}
	return nil
}

// DNSPod (Tencent Cloud API)
type dnspod struct {
	base
	secretID  string
	secretKey string
	region    string
	zone      string
	client    *http.Client
}

func newDNSPod(cfg Config) *dnspod {
	return &dnspod{secretID: cfg["secret_id"], secretKey: cfg["secret_key"], region: cfg["region"], zone: cfg["zone"], client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *dnspod) Name() string { return "dnspod" }

func (p *dnspod) Timeout() (time.Duration, time.Duration) { return 120 * time.Second, 3 * time.Second }

type dnspodEnvelope struct {
	Response json.RawMessage `json:"Response"`
}

type dnspodError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (p *dnspod) Present(domain, token, keyAuth string) error {
	fqdn, value, sub, zone, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	payload := map[string]any{"Domain": zone, "SubDomain": sub, "RecordType": "TXT", "RecordLine": "默认", "Value": value, "TTL": 600}
	var result struct {
		RecordID uint64 `json:"RecordId"`
	}
	if err := p.call("CreateRecord", payload, &result); err != nil {
		return err
	}
	if result.RecordID == 0 {
		return errors.New("DNSPod 创建 TXT 记录未返回 RecordId")
	}
	p.save(fqdn, value, strconv.FormatUint(result.RecordID, 10))
	if err := waitForTXT(context.Background(), fqdn, value, 90*time.Second); err != nil {
		_ = p.CleanUp(domain, token, keyAuth)
		return err
	}
	return nil
}

func (p *dnspod) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _, zone, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	id, ok := p.load(fqdn, value)
	if !ok {
		return nil
	}
	recordID, _ := strconv.ParseUint(id, 10, 64)
	err = p.call("DeleteRecord", map[string]any{"Domain": zone, "RecordId": recordID}, nil)
	if err == nil {
		p.remove(fqdn, value)
	}
	return err
}

func (p *dnspod) call(action string, payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	date := now.Format("2006-01-02")
	host := "dnspod.tencentcloudapi.com"
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + host + "\nx-tc-action:" + strings.ToLower(action) + "\n"
	signedHeaders := "content-type;host;x-tc-action"
	hashedPayload := sha256Hex(data)
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload
	scope := date + "/dnspod/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	secretDate := hmacSHA256([]byte("TC3"+p.secretKey), date)
	secretService := hmacSHA256(secretDate, "dnspod")
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))
	authorization := "TC3-HMAC-SHA256 Credential=" + p.secretID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", timestamp)
	req.Header.Set("X-TC-Version", "2021-03-23")
	if p.region != "" {
		req.Header.Set("X-TC-Region", p.region)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 DNSPod API 失败: %w", stripURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DNSPod API 返回 HTTP %d: %s", resp.StatusCode, truncate(string(body)))
	}
	var env dnspodEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("解析 DNSPod 响应失败: %w", err)
	}
	var e struct {
		Error *dnspodError `json:"Error"`
	}
	_ = json.Unmarshal(env.Response, &e)
	if e.Error != nil {
		return fmt.Errorf("DNSPod API 错误: %s (%s)", e.Error.Message, e.Error.Code)
	}
	if out != nil {
		if err := json.Unmarshal(env.Response, out); err != nil {
			return fmt.Errorf("解析 DNSPod 数据失败: %w", err)
		}
	}
	return nil
}

// AliDNS
type alidns struct {
	base
	accessKeyID     string
	accessKeySecret string
	zone            string
	client          *http.Client
}

func newAliDNS(cfg Config) *alidns {
	return &alidns{accessKeyID: cfg["access_key_id"], accessKeySecret: cfg["access_key_secret"], zone: cfg["zone"], client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *alidns) Name() string { return "alidns" }

func (p *alidns) Timeout() (time.Duration, time.Duration) { return 120 * time.Second, 3 * time.Second }

func (p *alidns) Present(domain, token, keyAuth string) error {
	fqdn, value, sub, zone, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	params := map[string]string{
		"DomainName": zone, "RR": sub, "Type": "TXT", "Value": value, "TTL": "600",
	}
	var result struct {
		RecordID string `json:"RecordId"`
	}
	if err := p.call("AddDomainRecord", params, &result); err != nil {
		return err
	}
	if result.RecordID == "" {
		return errors.New("阿里云 DNS 创建 TXT 记录未返回 RecordId")
	}
	p.save(fqdn, value, result.RecordID)
	if err := waitForTXT(context.Background(), fqdn, value, 90*time.Second); err != nil {
		_ = p.CleanUp(domain, token, keyAuth)
		return err
	}
	return nil
}

func (p *alidns) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, _, _, err := challengeRecord(domain, keyAuth, p.zone)
	if err != nil {
		return err
	}
	id, ok := p.load(fqdn, value)
	if !ok {
		return nil
	}
	err = p.call("DeleteDomainRecord", map[string]string{"RecordId": id}, nil)
	if err == nil {
		p.remove(fqdn, value)
	}
	return err
}

func (p *alidns) call(action string, params map[string]string, out any) error {
	all := map[string]string{
		"AccessKeyId": p.accessKeyID, "Action": action, "Format": "JSON",
		"SignatureMethod": "HMAC-SHA1", "SignatureNonce": strconv.FormatInt(time.Now().UnixNano(), 10),
		"SignatureVersion": "1.0", "Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version": "2015-01-09",
	}
	for k, v := range params {
		all[k] = v
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteString("&")
		}
		canonical.WriteString(aliPercent(k) + "=" + aliPercent(all[k]))
	}
	stringToSign := "GET&%2F&" + aliPercent(canonical.String())
	mac := hmac.New(sha1.New, []byte(p.accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	all["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	values := url.Values{}
	for k, v := range all {
		values.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodGet, "https://alidns.aliyuncs.com/?"+values.Encode(), nil)
	if err != nil {
		return errors.New("构造阿里云 DNS 请求失败")
	}
	req.Header.Set("User-Agent", "domain-manager/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求阿里云 DNS API 失败: %w", stripURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("阿里云 DNS API 返回 HTTP %d: %s", resp.StatusCode, truncate(string(body)))
	}
	var apiErr struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Code != "" {
		return fmt.Errorf("阿里云 DNS API 错误: %s (%s)", apiErr.Message, apiErr.Code)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("解析阿里云 DNS 响应失败: %w", err)
		}
	}
	return nil
}

func aliPercent(s string) string {
	s = url.QueryEscape(s)
	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "*", "%2A")
	s = strings.ReplaceAll(s, "%7E", "~")
	return s
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stripURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func truncate(s string) string {
	runes := []rune(s)
	if len(runes) > 400 {
		return string(runes[:400])
	}
	return s
}

var _ challenge.Provider = (*cloudflare)(nil)
var _ challenge.Provider = (*dnspod)(nil)
var _ challenge.Provider = (*alidns)(nil)
