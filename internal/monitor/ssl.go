package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

type SSLResult struct {
	HTTPSStatus   string
	Issuer        string
	Subject       string
	SerialNumber  string
	NotBefore     *time.Time
	NotAfter      *time.Time
	SAN           []string
	ChainValid    bool
	HostnameValid bool
	HTTPStatus    int
	Error         string
}

type SSLService struct {
	db       *gorm.DB
	settings *settings.Manager
	inFlight sync.Map
}

func NewSSLService(db *gorm.DB, st *settings.Manager) *SSLService {
	return &SSLService{db: db, settings: st}
}

func (s *SSLService) CheckOne(ctx context.Context, id uint, action string) (*models.SSLCertificate, error) {
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		return nil, err
	}
	if _, loaded := s.inFlight.LoadOrStore(cert.ID, struct{}{}); loaded {
		return &cert, errors.New("该证书监控正在检测中")
	}
	defer s.inFlight.Delete(cert.ID)

	start := time.Now()
	timeout := s.settings.Duration("http_timeout_seconds", 15*time.Second)
	allowPrivate := s.settings.Bool("allow_private_targets")
	cctx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()
	res, checkErr := checkSSLEndpoint(cctx, cert.Domain, cert.Port, cert.SNI, cert.SkipVerify, allowPrivate, timeout)
	now := time.Now()
	updates := map[string]any{
		"last_checked_at": now,
		"skip_verify":     cert.SkipVerify,
	}
	status := models.CertStatusUnreachable
	httpsStatus := "unreachable"
	if res != nil {
		httpsStatus = res.HTTPSStatus
		updates["https_status"] = res.HTTPSStatus
		updates["issuer"] = res.Issuer
		updates["subject"] = res.Subject
		updates["serial_number"] = res.SerialNumber
		updates["not_before"] = res.NotBefore
		updates["not_after"] = res.NotAfter
		updates["chain_valid"] = res.ChainValid
		updates["hostname_valid"] = res.HostnameValid
		if res.NotAfter != nil {
			days := security.DaysUntilIn(*res.NotAfter, s.settings.Location())
			updates["days_remaining"] = days
		}
		if san, err := json.Marshal(res.SAN); err == nil {
			updates["san"] = string(san)
		}
		if res.NotAfter != nil {
			switch {
			case res.NotAfter.Before(now):
				status = models.CertStatusExpired
			case !cert.SkipVerify && (!res.HostnameValid || !res.ChainValid):
				status = models.CertStatusInvalid
			case res.HTTPSStatus == "unreachable":
				status = models.CertStatusUnreachable
			case security.DaysUntilIn(*res.NotAfter, s.settings.Location()) <= s.settings.Int("ssl_warning_days"):
				status = models.CertStatusExpiring
			default:
				status = models.CertStatusNormal
			}
		} else {
			status = models.CertStatusFailed
		}
	}
	if checkErr != nil {
		updates["last_error"] = security.SanitizeText(checkErr.Error(), 1000)
		if res == nil {
			status = models.CertStatusUnreachable
			httpsStatus = "unreachable"
			updates["https_status"] = httpsStatus
		}
	} else {
		updates["last_error"] = ""
		if res != nil && res.Error != "" {
			updates["last_error"] = security.SanitizeText(res.Error, 1000)
		}
	}
	if res == nil {
		updates["https_status"] = httpsStatus
	}
	if cert.SkipVerify && status == models.CertStatusInvalid {
		status = models.CertStatusNormal
	}
	updates["status"] = status
	if err := s.db.Model(&models.SSLCertificate{}).Where("id = ?", cert.ID).Updates(updates).Error; err != nil {
		return nil, err
	}
	_ = s.db.First(&cert, cert.ID).Error

	logStatus := "success"
	message := fmt.Sprintf("证书检测成功，剩余 %d 天", cert.DaysRemaining)
	if checkErr != nil || res == nil || res.HTTPSStatus != "ok" || status == models.CertStatusUnreachable || status == models.CertStatusFailed || status == models.CertStatusInvalid || status == models.CertStatusExpired {
		logStatus = "failed"
		if cert.LastError != "" {
			message = cert.LastError
		}
	}
	details := fmt.Sprintf(`{"https_status":%q,"chain_valid":%t,"hostname_valid":%t,"skip_verify":%t}`,
		cert.HTTPSStatus, cert.ChainValid, cert.HostnameValid, cert.SkipVerify)
	s.log(cert.ID, cert.Domain, action, logStatus, message, time.Since(start), details)
	logger.L().Info("SSL 检测完成", "domain", cert.Domain, "port", cert.Port, "status", status, "days", cert.DaysRemaining, "error", cert.LastError)
	return &cert, nil
}

func (s *SSLService) CheckAll(ctx context.Context, action string) (CheckResult, error) {
	var certs []models.SSLCertificate
	if err := s.db.Where("monitor_enabled = ?", true).Find(&certs).Error; err != nil {
		return CheckResult{}, err
	}
	ids := make([]uint, 0, len(certs))
	for _, cert := range certs {
		ids = append(ids, cert.ID)
	}
	return s.CheckIDs(ctx, ids, action), nil
}

func (s *SSLService) CheckIDs(ctx context.Context, ids []uint, action string) CheckResult {
	result := CheckResult{}
	max := s.settings.Int("max_concurrency")
	if max < 1 {
		max = 5
	}
	sem := make(chan struct{}, max)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, id := range ids {
		id := id
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("检测发生内部异常: %v", r)
						logger.L().Error("SSL 检测 goroutine panic", "certificate_id", id, "panic", r)
					}
				}()
				_, err = s.CheckOne(ctx, id, action)
			}()
			mu.Lock()
			if err != nil {
				if err.Error() == "该证书监控正在检测中" {
					result.Skipped++
				} else {
					result.Failed++
				}
			} else {
				result.Success++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return result
}

func (s *SSLService) CheckByIDs(ctx context.Context, ids []uint, action string) (CheckResult, error) {
	var result CheckResult
	for _, id := range ids {
		if _, err := s.CheckOne(ctx, id, action); err != nil {
			if err.Error() == "该证书监控正在检测中" {
				result.Skipped++
			} else {
				result.Failed++
			}
		} else {
			result.Success++
		}
	}
	return result, nil
}

func checkSSLEndpoint(ctx context.Context, domain string, port int, sni string, skipVerify, allowPrivate bool, timeout time.Duration) (*SSLResult, error) {
	if port <= 0 || port > 65535 {
		return nil, errors.New("HTTPS 端口无效")
	}
	if sni == "" {
		sni = domain
	}
	addr := net.JoinHostPort(domain, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
		Control:   security.SafeControl(allowPrivate),
	}
	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName:         sni,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // diagnostic retrieval; chain is verified manually below
		},
	}
	conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS 连接失败: %w", err)
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, errors.New("TLS 连接类型异常")
	}
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("服务器未返回证书")
	}
	leaf := state.PeerCertificates[0]
	res := &SSLResult{
		HTTPSStatus:  "ok",
		Issuer:       leaf.Issuer.CommonName,
		Subject:      leaf.Subject.CommonName,
		SerialNumber: leaf.SerialNumber.Text(16),
		NotAfter:     &leaf.NotAfter,
		NotBefore:    &leaf.NotBefore,
		SAN:          append([]string{}, leaf.DNSNames...),
	}
	if len(res.SAN) == 0 && leaf.Subject.CommonName != "" {
		res.SAN = []string{leaf.Subject.CommonName}
	}
	for _, ip := range leaf.IPAddresses {
		res.SAN = append(res.SAN, ip.String())
	}
	if err := leaf.VerifyHostname(sni); err == nil {
		res.HostnameValid = true
	}
	intermediates := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}); err == nil {
		res.ChainValid = true
	}
	// In skip-verify diagnostic mode the fields above are still populated, but
	// the monitor status ignores chain/hostname validation failures.
	_ = skipVerify

	transport := security.NewSafeTransport(allowPrivate, timeout, true)
	transport.TLSClientConfig.ServerName = sni
	transport.TLSClientConfig.InsecureSkipVerify = true
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "https://" + net.JoinHostPort(domain, strconv.Itoa(port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "domain-manager/1.0 SSL monitor")
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			res.HTTPSStatus = "unreachable"
			res.Error = "HTTPS 请求失败: " + reqErr.Error()
		} else {
			res.HTTPStatus = resp.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				res.HTTPSStatus = "server_error"
				res.Error = fmt.Sprintf("HTTPS 服务返回 HTTP %d", resp.StatusCode)
			}
		}
	}
	transport.CloseIdleConnections()
	return res, nil
}

func (s *SSLService) log(id uint, target, action, status, message string, duration time.Duration, details string) {
	_ = s.db.Create(&models.MonitorLog{
		Kind: "ssl", TargetID: id, Target: target, Action: action, Status: status,
		Message: security.SanitizeText(message, 2000), DurationMS: duration.Milliseconds(),
		Details: details,
	}).Error
}

// SANList returns the parsed SAN list for API responses.
func SANList(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return []string{}
	}
	return out
}
