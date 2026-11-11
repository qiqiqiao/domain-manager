package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"domain-manager/internal/acme/dns"
	certstore "domain-manager/internal/certificate"
	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/notification"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"github.com/go-acme/lego/v4/certcrypto"
	legocert "github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	http01legacy "github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"gorm.io/gorm"
)

const (
	letsEncryptStaging    = lego.LEDirectoryStaging
	letsEncryptProduction = lego.LEDirectoryProduction
)

type ApplyRequest struct {
	Domains       []string          `json:"domains"`
	Email         string            `json:"email"`
	ChallengeType string            `json:"challenge_type"`
	DNSProvider   string            `json:"dns_provider"`
	DNSConfig     map[string]string `json:"dns_config"`
	KeyType       string            `json:"key_type"`
	Staging       *bool             `json:"staging"`
	AgreeTOS      bool              `json:"agree_tos"`
	AutoRenew     *bool             `json:"auto_renew"`
}

type Service struct {
	db       *gorm.DB
	settings *settings.Manager
	cipher   *security.Cipher
	certs    *certstore.Service
	notifier *notification.Service
	dataDir  string
	sem      chan struct{}
	running  sync.Map
	renewing sync.Map
	applyMu  sync.Mutex
	renewMu  sync.Mutex
}

func NewService(db *gorm.DB, st *settings.Manager, cipher *security.Cipher, certs *certstore.Service, notifier *notification.Service, dataDir string) *Service {
	concurrency := st.Int("acme_concurrency")
	if concurrency < 1 {
		concurrency = 2
	}
	return &Service{
		db: db, settings: st, cipher: cipher, certs: certs, notifier: notifier,
		dataDir: dataDir, sem: make(chan struct{}, concurrency),
	}
}

type accountUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *accountUser) GetEmail() string                        { return u.email }
func (u *accountUser) GetRegistration() *registration.Resource { return u.reg }
func (u *accountUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (s *Service) Apply(ctx context.Context, req ApplyRequest) (*models.CertificateOrder, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !req.AgreeTOS {
		return nil, errors.New("必须同意 ACME 服务商服务条款")
	}
	if len(req.Domains) == 0 {
		return nil, errors.New("至少需要一个域名")
	}
	if len(req.Domains) > 100 {
		return nil, errors.New("单个证书最多支持 100 个域名")
	}
	seen := map[string]bool{}
	var domains []string
	for _, raw := range req.Domains {
		d, err := security.NormalizeDomain(raw, true)
		if err != nil {
			return nil, fmt.Errorf("域名 %q 无效: %w", raw, err)
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return nil, errors.New("没有有效域名")
	}
	challenge := strings.ToLower(strings.TrimSpace(req.ChallengeType))
	switch challenge {
	case "http-01", "http01":
		challenge = "http-01"
		for _, d := range domains {
			if strings.HasPrefix(d, "*.") {
				return nil, errors.New("通配符证书必须使用 DNS-01 验证")
			}
		}
	case "dns-01", "dns01":
		challenge = "dns-01"
	default:
		return nil, errors.New("验证方式必须为 http-01 或 dns-01")
	}
	provider := strings.TrimSpace(req.DNSProvider)
	if challenge == "dns-01" {
		if err := dns.Validate(provider, dns.Config(req.DNSConfig)); err != nil {
			return nil, err
		}
	} else {
		provider = ""
		req.DNSConfig = nil
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = strings.TrimSpace(s.settings.Get("acme_email"))
	}
	if email == "" {
		return nil, errors.New("请配置 ACME 账号邮箱")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return nil, errors.New("ACME 邮箱格式无效")
	}
	keyType := strings.ToLower(strings.TrimSpace(req.KeyType))
	if keyType == "" {
		keyType = s.settings.Get("acme_key_type")
	}
	switch keyType {
	case "rsa2048", "rsa4096", "ec256", "ec384":
	default:
		return nil, errors.New("不支持的证书密钥类型")
	}
	staging := true
	if req.Staging != nil {
		staging = *req.Staging
	} else if s.settings.Get("acme_staging") == "false" {
		staging = false
	}
	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}
	maxAttempts := s.settings.Int("acme_max_attempts")
	if maxAttempts < 1 {
		maxAttempts = 3
	}

	var active int64
	if err := s.db.Model(&models.CertificateOrder{}).
		Where("primary_domain = ? AND status IN ?", domains[0], []string{"pending", "running"}).
		Count(&active).Error; err != nil {
		return nil, err
	}
	if active > 0 {
		return nil, errors.New("该主域名已有正在处理的证书订单")
	}

	dnsJSON := ""
	if challenge == "dns-01" {
		data, _ := json.Marshal(req.DNSConfig)
		dnsJSON, err = s.cipher.Encrypt(string(data))
		if err != nil {
			return nil, err
		}
	}
	domainsJSON, _ := json.Marshal(domains)
	order := &models.CertificateOrder{
		PrimaryDomain: domains[0], DomainsJSON: string(domainsJSON), ChallengeType: challenge,
		DNSProvider: provider, DNSConfigEnc: dnsJSON, KeyType: keyType, Email: email,
		Staging: staging, AutoRenew: autoRenew, Status: "pending", MaxAttempts: maxAttempts,
	}
	s.appendLog(order, fmt.Sprintf("订单已创建：域名 %s，验证方式 %s，环境 %s", strings.Join(domains, ", "), challenge, environmentName(staging)))
	if err := s.db.Create(order).Error; err != nil {
		return nil, err
	}
	go s.ProcessOrder(context.Background(), order.ID)
	return order, nil
}

func (s *Service) ProcessOrder(ctx context.Context, orderID uint) {
	if _, loaded := s.running.LoadOrStore(orderID, true); loaded {
		return
	}
	defer s.running.Delete(orderID)
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	var order models.CertificateOrder
	defer func() {
		if r := recover(); r != nil {
			logger.L().Error("ACME 订单处理发生 panic", "order_id", orderID, "panic", r)
			if order.ID != 0 {
				s.failOrder(&order, fmt.Errorf("订单处理内部异常: %v", r))
			}
		}
	}()

	result := s.db.Model(&models.CertificateOrder{}).
		Where("id = ? AND status IN ?", orderID, []string{"pending", "failed"}).
		Updates(map[string]any{"status": "running", "started_at": time.Now(), "last_error": ""})
	if result.Error != nil || result.RowsAffected == 0 {
		return
	}
	if err := s.db.First(&order, orderID).Error; err != nil {
		return
	}
	s.appendLog(&order, "开始处理证书订单")
	workCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	if err := s.issue(workCtx, &order); err != nil {
		s.failOrder(&order, err)
		return
	}
}

type orderContext struct {
	order  *models.CertificateOrder
	client *lego.Client
}

func (s *Service) issue(ctx context.Context, order *models.CertificateOrder) error {
	var domains []string
	if err := json.Unmarshal([]byte(order.DomainsJSON), &domains); err != nil || len(domains) == 0 {
		return errors.New("订单域名数据损坏")
	}
	cfg, err := s.prepareClient(ctx, order)
	if err != nil {
		return err
	}
	switch order.ChallengeType {
	case "http-01":
		mode := s.settings.Get("acme_http01_mode")
		if mode == "webroot" {
			provider, err := newWebrootProvider(s.settings.Get("acme_webroot"))
			if err != nil {
				return err
			}
			if err := cfg.client.Challenge.SetHTTP01Provider(provider); err != nil {
				return err
			}
			s.appendLog(order, "HTTP-01 使用 Webroot 模式，请确认外部 Web 服务器已正确提供验证路径")
		} else {
			iface := s.settings.Get("acme_http01_iface")
			port := s.settings.Get("acme_http01_port")
			provider := http01legacy.NewProviderServer(iface, port)
			if err := cfg.client.Challenge.SetHTTP01Provider(provider); err != nil {
				return err
			}
			s.appendLog(order, fmt.Sprintf("HTTP-01 使用内置服务器监听 %s:%s，必须确保公网可访问 80 端口（或已做端口映射）", iface, port))
		}
	case "dns-01":
		plain, err := s.cipher.Decrypt(order.DNSConfigEnc)
		if err != nil {
			return errors.New("DNS API 凭据解密失败")
		}
		dnsCfg, err := dns.ParseConfig(plain)
		if err != nil {
			return err
		}
		provider, err := dns.New(order.DNSProvider, dnsCfg)
		if err != nil {
			return err
		}
		if err := cfg.client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}),
			dns01.AddDNSTimeout(30*time.Second),
		); err != nil {
			return err
		}
		s.appendLog(order, "DNS-01 已启用，正在通过 DNS API 创建并检查 TXT 记录")
	default:
		return errors.New("不支持的验证方式")
	}

	s.appendLog(order, "正在向 ACME 服务提交证书请求，请等待验证结果")
	certRes, err := cfg.client.Certificate.Obtain(legocert.ObtainRequest{
		Domains: domains, Bundle: true, PreferredChain: "",
	})
	if err != nil {
		return fmt.Errorf("ACME 签发失败: %w", err)
	}
	leaf, err := certstore.ParseLeaf(certRes.Certificate)
	if err != nil {
		return fmt.Errorf("解析签发证书失败: %w", err)
	}
	cert, files, err := s.saveCertificate(order, leaf, certRes)
	if err != nil {
		return err
	}
	now := time.Now()
	updates := map[string]any{
		"status": "valid", "last_error": "", "completed_at": now,
		"not_before": leaf.NotBefore, "not_after": leaf.NotAfter, "next_retry_at": nil,
		"cert_id": cert.ID,
	}
	if err := s.db.Model(&models.CertificateOrder{}).Where("id = ?", order.ID).Updates(updates).Error; err != nil {
		return err
	}
	order.NotBefore, order.NotAfter = &leaf.NotBefore, &leaf.NotAfter
	order.CertID = &cert.ID
	if order.RenewalOf != nil {
		_ = s.db.Model(&models.CertificateOrder{}).Where("id = ?", *order.RenewalOf).Update("status", "renewed").Error
	}
	// A newer certificate replaces every other valid order for the same
	// monitored endpoint. This prevents old staging/production orders from
	// triggering a duplicate automatic renewal later.
	_ = s.db.Model(&models.CertificateOrder{}).
		Where("cert_id = ? AND id <> ? AND status = ?", cert.ID, order.ID, "valid").
		Update("status", "renewed").Error
	s.appendLog(order, fmt.Sprintf("证书签发成功，有效期至 %s", leaf.NotAfter.In(s.settings.Location()).Format("2006-01-02 15:04:05")))
	logger.L().Info("ACME 证书签发成功", "order_id", order.ID, "domains", order.PrimaryDomain, "not_after", leaf.NotAfter)

	if s.settings.Bool("auto_deploy") {
		if dir, err := s.certs.Deploy(ctx, cert); err != nil {
			s.appendLog(order, "自动部署失败: "+err.Error())
			s.notifier.NotifyEvent(ctx, models.EventSystemError, cert.Domain,
				fmt.Sprintf("deploy:%d:%d", order.ID, time.Now().Unix()), "【证书自动部署失败】",
				fmt.Sprintf("域名：%s\n订单：#%d\n错误：%s\n\n证书已签发，但文件部署失败，请检查部署配置。", cert.Domain, order.ID, err.Error()))
		} else {
			s.appendLog(order, "证书已自动部署至 "+dir)
		}
	}
	event := models.EventCertIssued
	title := "【SSL 证书申请成功】"
	if order.RenewalOf != nil {
		event = models.EventCertRenewed
		title = "【SSL 证书续期成功】"
	}
	content := fmt.Sprintf("域名：%s\n\n证书颁发机构：%s\n证书到期时间：%s\n验证方式：%s\n环境：%s\n订单编号：#%d",
		strings.Join(domains, ", "), leaf.Issuer.CommonName, leaf.NotAfter.In(s.settings.Location()).Format("2006-01-02"), order.ChallengeType, environmentName(order.Staging), order.ID)
	s.notifier.NotifyEvent(ctx, event, order.PrimaryDomain, fmt.Sprintf("%s:%d", event, order.ID), title, content)
	_ = files
	return nil
}

func (s *Service) prepareClient(ctx context.Context, order *models.CertificateOrder) (*orderContext, error) {
	directory := letsEncryptProduction
	if order.Staging {
		directory = letsEncryptStaging
	}
	keyPath, reg, err := s.loadAccount(order.Email, directory)
	if err != nil {
		return nil, err
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读取 ACME 账号密钥失败: %w", err)
	}
	privateKey, err := certcrypto.ParsePEMPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("解析 ACME 账号密钥失败: %w", err)
	}
	user := &accountUser{email: order.Email, key: privateKey, reg: reg}
	config := lego.NewConfig(user)
	config.CADirURL = directory
	config.UserAgent = "domain-manager/1.0"
	config.HTTPClient = security.NewSafeHTTPClient(s.settings.Bool("allow_private_targets"), 2*time.Minute)
	config.Certificate.KeyType = keyType(order.KeyType)
	config.Certificate.Timeout = 5 * time.Minute
	config.Certificate.OverallRequestLimit = 10
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("创建 ACME 客户端失败: %w", err)
	}
	if user.reg == nil {
		s.appendLog(order, "正在注册 ACME 账号并同意服务条款")
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("注册 ACME 账号失败: %w", err)
		}
		user.reg = reg
		raw, _ := json.Marshal(reg)
		var account models.ACMEAccount
		now := time.Now()
		if err := s.db.Where("email = ? AND directory_url = ?", order.Email, directory).First(&account).Error; err != nil {
			account = models.ACMEAccount{
				Email: order.Email, DirectoryURL: directory, Staging: order.Staging,
				KeyPath: keyPath, RegistrationJSON: string(raw), Status: "active",
			}
			if err := s.db.Create(&account).Error; err != nil {
				return nil, err
			}
		} else {
			_ = s.db.Model(&account).Updates(map[string]any{
				"key_path": keyPath, "registration_json": string(raw), "status": "active", "last_used_at": now,
			}).Error
		}
		s.appendLog(order, "ACME 账号注册成功")
	} else {
		_ = s.db.Model(&models.ACMEAccount{}).
			Where("email = ? AND directory_url = ?", order.Email, directory).
			Updates(map[string]any{"last_used_at": time.Now(), "status": "active"}).Error
	}
	_ = ctx
	return &orderContext{order: order, client: client}, nil
}

func (s *Service) loadAccount(email, directory string) (string, *registration.Resource, error) {
	sum := sha256.Sum256([]byte(strings.ToLower(email) + "|" + directory))
	dir := filepath.Join(s.dataDir, "acme", "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	keyPath := filepath.Join(dir, hex.EncodeToString(sum[:12])+".key")
	var reg *registration.Resource
	var account models.ACMEAccount
	err := s.db.Where("email = ? AND directory_url = ?", email, directory).First(&account).Error
	if err == nil && account.RegistrationJSON != "" {
		var parsed registration.Resource
		if json.Unmarshal([]byte(account.RegistrationJSON), &parsed) == nil && parsed.URI != "" {
			reg = &parsed
		}
	}
	if _, statErr := os.Stat(keyPath); statErr != nil {
		key, genErr := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
		if genErr != nil {
			return "", nil, fmt.Errorf("生成 ACME 账号密钥失败: %w", genErr)
		}
		data := certcrypto.PEMEncode(key)
		if err := os.WriteFile(keyPath, data, 0o600); err != nil {
			return "", nil, fmt.Errorf("保存 ACME 账号密钥失败: %w", err)
		}
		_ = os.Chmod(keyPath, 0o600)
		reg = nil
	}
	return keyPath, reg, nil
}

func (s *Service) saveCertificate(order *models.CertificateOrder, leaf *x509.Certificate, certRes *legocert.Resource) (*models.SSLCertificate, *certstore.StoredFiles, error) {
	monitorDomain, canMonitor := certificateMonitorDomain(order)
	var cert models.SSLCertificate
	err := s.db.Where("domain = ? AND port = ?", monitorDomain, 443).First(&cert).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		cert = models.SSLCertificate{
			Domain: monitorDomain, Port: 443, MonitorEnabled: canMonitor,
			Source: "acme", Status: models.CertStatusPending, HTTPSStatus: "not_checked",
		}
		var domain models.Domain
		if e := s.db.Where("name = ?", monitorDomain).First(&domain).Error; e == nil {
			cert.DomainID = &domain.ID
		}
		if err := s.db.Create(&cert).Error; err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	files, err := s.certs.StoreFiles(cert.ID, certRes.PrivateKey, certRes.Certificate, certRes.IssuerCertificate)
	if err != nil {
		return nil, nil, err
	}
	san := append([]string{}, leaf.DNSNames...)
	if len(san) == 0 && leaf.Subject.CommonName != "" {
		san = []string{leaf.Subject.CommonName}
	}
	sanJSON, _ := json.Marshal(san)
	days := security.DaysUntilIn(leaf.NotAfter, s.settings.Location())
	status := models.CertStatusNormal
	if days < 0 {
		status = models.CertStatusExpired
	} else if days <= s.settings.Int("ssl_warning_days") {
		status = models.CertStatusExpiring
	}
	updates := map[string]any{
		"managed": true, "auto_renew": order.AutoRenew, "source": "acme", "order_id": order.ID,
		"issuer": leaf.Issuer.CommonName, "subject": leaf.Subject.CommonName,
		"serial_number": leaf.SerialNumber.Text(16), "not_before": leaf.NotBefore, "not_after": leaf.NotAfter,
		"days_remaining": days, "san": string(sanJSON), "chain_valid": true, "hostname_valid": true,
		"status": status, "last_error": "", "last_checked_at": nil,
		"cert_path": files.CertPath, "key_path": files.KeyPath, "fullchain_path": files.FullchainPath,
	}
	if !canMonitor {
		updates["monitor_enabled"] = false
	}
	if err := s.db.Model(&models.SSLCertificate{}).Where("id = ?", cert.ID).Updates(updates).Error; err != nil {
		return nil, nil, err
	}
	if err := s.db.First(&cert, cert.ID).Error; err != nil {
		return nil, nil, err
	}
	return &cert, files, nil
}

// certificateMonitorDomain picks a concrete SAN for HTTPS checking. A
// wildcard-only certificate has no hostname that can be dialed directly, so it
// is still stored as a managed certificate record but remote checking stays
// disabled.
func certificateMonitorDomain(order *models.CertificateOrder) (string, bool) {
	var domains []string
	_ = json.Unmarshal([]byte(order.DomainsJSON), &domains)
	for _, domain := range domains {
		if !strings.HasPrefix(domain, "*.") {
			return domain, true
		}
	}
	if len(domains) > 0 {
		return domains[0], false
	}
	return order.PrimaryDomain, false
}

func keyType(raw string) certcrypto.KeyType {
	switch raw {
	case "rsa4096":
		return certcrypto.RSA4096
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	default:
		return certcrypto.RSA2048
	}
}

func environmentName(staging bool) string {
	if staging {
		return "Let's Encrypt Staging（测试）"
	}
	return "Let's Encrypt Production（生产）"
}

func (s *Service) appendLog(order *models.CertificateOrder, message string) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), security.SanitizeText(message, 3000))
	order.Logs += line
	order.Logs = security.TruncateTailRunes(order.Logs, 100*1024)
	if order.ID != 0 {
		_ = s.db.Model(&models.CertificateOrder{}).Where("id = ?", order.ID).Update("logs", order.Logs).Error
	}
}

func (s *Service) failOrder(order *models.CertificateOrder, err error) {
	message := security.SanitizeText(err.Error(), 2000)
	attempts := order.Attempts + 1
	maxAttempts := order.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 3
	}
	updates := map[string]any{
		"status": "failed", "last_error": message, "attempts": attempts,
		"next_retry_at": nil,
	}
	if attempts < maxAttempts {
		delay := time.Duration(6*(1<<uint(attempts-1))) * time.Hour
		if delay > 72*time.Hour {
			delay = 72 * time.Hour
		}
		next := time.Now().Add(delay)
		updates["next_retry_at"] = next
	}
	order.Attempts = attempts
	if err := s.db.Model(&models.CertificateOrder{}).Where("id = ?", order.ID).Updates(updates).Error; err != nil {
		logger.L().Error("更新证书订单失败状态出错", "error", err)
	}
	s.appendLog(order, "订单处理失败: "+message)
	logger.L().Error("ACME 证书订单失败", "order_id", order.ID, "domain", order.PrimaryDomain, "error", message)
	title := "【SSL 证书申请失败】"
	if order.RenewalOf != nil {
		title = "【SSL 证书续期失败】"
	}
	content := fmt.Sprintf("域名：%s\n订单编号：#%d\n尝试次数：%d/%d\n\n失败原因：\n%s",
		order.PrimaryDomain, order.ID, attempts, maxAttempts, message)
	if updates["next_retry_at"] != nil {
		content += "\n\n系统将按指数退避策略自动重试，以遵守 ACME CA 限流策略。"
	} else {
		content += "\n\n已达到最大自动重试次数，请检查配置后手动重试。"
	}
	s.notifier.NotifyEvent(context.Background(), models.EventCertFailed, order.PrimaryDomain,
		fmt.Sprintf("cert_failed:%d:%d", order.ID, attempts), title, content)
}

func (s *Service) RetryDue(ctx context.Context) (int, error) {
	now := time.Now()
	var orders []models.CertificateOrder
	if err := s.db.Where("status = ? AND created_at <= ?", "pending", now.Add(-2*time.Minute)).Limit(20).Find(&orders).Error; err != nil {
		return 0, err
	}
	var retry []models.CertificateOrder
	if err := s.db.Where("status = ? AND attempts < max_attempts AND next_retry_at IS NOT NULL AND next_retry_at <= ?", "failed", now).
		Limit(20).Find(&retry).Error; err != nil {
		return 0, err
	}
	orders = append(orders, retry...)
	count := 0
	for i := range orders {
		id := orders[i].ID
		go s.ProcessOrder(context.Background(), id)
		count++
	}
	_ = ctx
	return count, nil
}

func (s *Service) RecoverStuck() error {
	return s.db.Model(&models.CertificateOrder{}).Where("status = ?", "running").
		Updates(map[string]any{"status": "failed", "last_error": "程序重启导致任务中断，将自动重试", "next_retry_at": time.Now().Add(time.Minute)}).Error
}

func (s *Service) ManualRetry(ctx context.Context, orderID uint) error {
	var order models.CertificateOrder
	if err := s.db.First(&order, orderID).Error; err != nil {
		return err
	}
	if order.Status == "valid" || order.Status == "running" {
		return errors.New("该订单当前状态不允许重试")
	}
	if err := s.db.Model(&order).Updates(map[string]any{
		"status": "pending", "attempts": 0, "next_retry_at": nil, "last_error": "",
	}).Error; err != nil {
		return err
	}
	s.appendLog(&order, "管理员手动触发重试")
	go s.ProcessOrder(context.Background(), order.ID)
	return nil
}

func (s *Service) RenewCertificate(ctx context.Context, certID uint) (*models.CertificateOrder, error) {
	return s.renewCertificate(ctx, certID, false)
}

func (s *Service) renewCertificate(ctx context.Context, certID uint, automatic bool) (*models.CertificateOrder, error) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	var cert models.SSLCertificate
	if err := s.db.First(&cert, certID).Error; err != nil {
		return nil, err
	}
	if !cert.Managed {
		return nil, errors.New("该证书不是 ACME 托管证书，无法自动续期")
	}
	var source models.CertificateOrder
	if cert.OrderID != nil {
		_ = s.db.First(&source, *cert.OrderID).Error
	}
	if source.ID == 0 {
		if err := s.db.Where("cert_id = ? AND status IN ?", cert.ID, []string{"valid", "renewed"}).Order("id DESC").First(&source).Error; err != nil {
			return nil, errors.New("未找到可复用的 ACME 订单配置")
		}
	}
	blocked, err := s.hasActiveRenewal(source.ID, automatic)
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, errors.New("该证书已有续期订单正在处理")
	}
	order := &models.CertificateOrder{
		PrimaryDomain: source.PrimaryDomain, DomainsJSON: source.DomainsJSON, ChallengeType: source.ChallengeType,
		DNSProvider: source.DNSProvider, DNSConfigEnc: source.DNSConfigEnc, KeyType: source.KeyType,
		Email: source.Email, Staging: source.Staging, AutoRenew: cert.AutoRenew, Status: "pending",
		MaxAttempts: source.MaxAttempts, RenewalOf: &source.ID,
	}
	if order.MaxAttempts < 1 {
		order.MaxAttempts = 3
	}
	s.appendLog(order, "创建续期订单")
	if err := s.db.Create(order).Error; err != nil {
		return nil, err
	}
	go s.ProcessOrder(context.Background(), order.ID)
	return order, nil
}

// hasActiveRenewal decides whether a new renewal order may be created.
// Pending/running orders always block. Failed orders block while they still
// have automatic retries left, or during a short cooldown after their retries
// are exhausted. Without the cooldown check an exhausted order would block
// automatic renewal forever.
func (s *Service) hasActiveRenewal(sourceID uint, automatic bool) (bool, error) {
	var active int64
	if err := s.db.Model(&models.CertificateOrder{}).
		Where("renewal_of = ? AND status IN ?", sourceID, []string{"pending", "running"}).
		Count(&active).Error; err != nil {
		return false, err
	}
	if active > 0 {
		return true, nil
	}
	if !automatic {
		return false, nil
	}
	cooldownHours := s.settings.Int("acme_renew_cooldown_hours")
	if cooldownHours <= 0 {
		cooldownHours = 24
	}
	cutoff := time.Now().Add(-time.Duration(cooldownHours) * time.Hour)
	var blocking int64
	if err := s.db.Model(&models.CertificateOrder{}).
		Where("renewal_of = ? AND status = ? AND (attempts < max_attempts OR updated_at > ?)",
			sourceID, "failed", cutoff).
		Count(&blocking).Error; err != nil {
		return false, err
	}
	return blocking > 0, nil
}

func (s *Service) RenewDue(ctx context.Context) (int, error) {
	renewDays := s.settings.Int("acme_renew_days")
	if renewDays <= 0 {
		renewDays = 30
	}
	limitDate := time.Now().AddDate(0, 0, renewDays)
	var orders []models.CertificateOrder
	if err := s.db.Where("status = ? AND auto_renew = ? AND cert_id IS NOT NULL AND not_after IS NOT NULL AND not_after <= ?", "valid", true, limitDate).
		Limit(20).Find(&orders).Error; err != nil {
		return 0, err
	}
	count := 0
	for i := range orders {
		order := orders[i]
		if order.CertID == nil {
			continue
		}
		var cert models.SSLCertificate
		if err := s.db.First(&cert, *order.CertID).Error; err != nil || !cert.Managed || !cert.AutoRenew {
			continue
		}
		if _, loaded := s.renewing.LoadOrStore(cert.ID, true); loaded {
			continue
		}
		_, err := s.renewCertificate(ctx, cert.ID, true)
		s.renewing.Delete(cert.ID)
		if err == nil {
			count++
		} else {
			logger.L().Warn("自动续期创建订单失败", "domain", cert.Domain, "error", err)
		}
	}
	return count, nil
}

func (s *Service) Orders(limit int) ([]models.CertificateOrder, error) {
	var orders []models.CertificateOrder
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	err := s.db.Order("id DESC").Limit(limit).Find(&orders).Error
	return orders, err
}

func (s *Service) BuildProductionCheck() error {
	if _, err := strconv.Atoi(s.settings.Get("acme_http01_port")); err != nil {
		return errors.New("HTTP-01 端口配置无效")
	}
	return nil
}
