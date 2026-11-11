package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"domain-manager/internal/acme"
	"domain-manager/internal/models"
	"domain-manager/internal/monitor"
	"domain-manager/internal/security"

	"github.com/gin-gonic/gin"
)

type certificateRequest struct {
	Domain         string `json:"domain" binding:"required"`
	Port           int    `json:"port"`
	SNI            string `json:"sni"`
	SkipVerify     bool   `json:"skip_verify"`
	MonitorEnabled *bool  `json:"monitor_enabled"`
}

func (s *Server) listCertificates(c *gin.Context) {
	page, size := pageParams(c)
	query := s.db.Model(&models.SSLCertificate{})
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		query = query.Where("domain LIKE ? OR issuer LIKE ?", "%"+search+"%", "%"+search+"%")
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if managed := c.Query("managed"); managed != "" {
		if b, err := strconv.ParseBool(managed); err == nil {
			query = query.Where("managed = ?", b)
		}
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		serverError(c, err)
		return
	}
	var certs []models.SSLCertificate
	if err := query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&certs).Error; err != nil {
		serverError(c, err)
		return
	}
	items := make([]gin.H, 0, len(certs))
	for i := range certs {
		items = append(items, certView(&certs[i]))
	}
	ok(c, paginated(items, total, page, size))
}

func (s *Server) getCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	ok(c, certView(&cert))
}

func certView(cert *models.SSLCertificate) gin.H {
	days := cert.DaysRemaining
	if cert.NotAfter != nil {
		days = computeDays(cert.NotAfter)
	}
	return gin.H{
		"id": cert.ID, "domain_id": cert.DomainID, "domain": cert.Domain, "port": cert.Port,
		"sni": cert.SNI, "skip_verify": cert.SkipVerify, "status": cert.Status,
		"https_status": cert.HTTPSStatus, "issuer": cert.Issuer, "subject": cert.Subject,
		"serial_number": cert.SerialNumber, "not_before": cert.NotBefore, "not_after": cert.NotAfter,
		"days_remaining": days, "san": monitor.SANList(cert.SAN), "chain_valid": cert.ChainValid,
		"hostname_valid": cert.HostnameValid, "monitor_enabled": cert.MonitorEnabled,
		"managed": cert.Managed, "auto_renew": cert.AutoRenew, "source": cert.Source,
		"order_id": cert.OrderID, "has_private_key": cert.KeyPath != "",
		"last_checked_at": cert.LastCheckedAt, "last_error": cert.LastError,
		"created_at": cert.CreatedAt, "updated_at": cert.UpdatedAt,
	}
}

func (s *Server) createCertificate(c *gin.Context) {
	var req certificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请填写域名")
		return
	}
	name, err := security.NormalizeDomain(req.Domain, false)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	port := req.Port
	if port == 0 {
		port = s.settings.Int("ssl_default_port")
		if port == 0 {
			port = 443
		}
	}
	if port < 1 || port > 65535 {
		badRequest(c, "端口必须在 1-65535 之间")
		return
	}
	sni := ""
	if strings.TrimSpace(req.SNI) != "" {
		sni, err = security.NormalizeDomain(req.SNI, false)
		if err != nil {
			badRequest(c, "SNI 域名无效: "+err.Error())
			return
		}
	}
	enabled := true
	if req.MonitorEnabled != nil {
		enabled = *req.MonitorEnabled
	}
	cert := models.SSLCertificate{
		Domain: name, Port: port, SNI: sni, SkipVerify: req.SkipVerify,
		MonitorEnabled: enabled, Source: "monitor", Status: models.CertStatusPending, HTTPSStatus: "unknown",
	}
	if err := s.db.Create(&cert).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			conflict(c, "该域名与端口已存在监控记录")
		} else {
			serverError(c, err)
		}
		return
	}
	go s.ssl.CheckIDs(context.Background(), []uint{cert.ID}, "auto")
	created(c, certView(&cert))
}

func (s *Server) updateCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	var req struct {
		Port           *int    `json:"port"`
		SNI            *string `json:"sni"`
		SkipVerify     *bool   `json:"skip_verify"`
		MonitorEnabled *bool   `json:"monitor_enabled"`
		AutoRenew      *bool   `json:"auto_renew"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求参数无效")
		return
	}
	updates := map[string]any{}
	if req.Port != nil {
		if *req.Port < 1 || *req.Port > 65535 {
			badRequest(c, "端口必须在 1-65535 之间")
			return
		}
		updates["port"] = *req.Port
	}
	if req.SNI != nil {
		if strings.TrimSpace(*req.SNI) == "" {
			updates["sni"] = ""
		} else {
			sni, err := security.NormalizeDomain(*req.SNI, false)
			if err != nil {
				badRequest(c, "SNI 域名无效")
				return
			}
			updates["sni"] = sni
		}
	}
	if req.SkipVerify != nil {
		updates["skip_verify"] = *req.SkipVerify
	}
	if req.MonitorEnabled != nil {
		updates["monitor_enabled"] = *req.MonitorEnabled
	}
	if req.AutoRenew != nil {
		if !cert.Managed && *req.AutoRenew {
			badRequest(c, "只有 ACME 托管证书可以开启自动续期")
			return
		}
		updates["auto_renew"] = *req.AutoRenew
	}
	if len(updates) > 0 {
		if err := s.db.Model(&cert).Updates(updates).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				conflict(c, "该域名与端口已存在监控记录")
			} else {
				serverError(c, err)
			}
			return
		}
	}
	_ = s.db.First(&cert, id).Error
	ok(c, certView(&cert))
}

func (s *Server) deleteCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	if err := s.certs.DeleteFiles(&cert); err != nil {
		serverError(c, err)
		return
	}
	if err := s.db.Delete(&cert).Error; err != nil {
		serverError(c, err)
		return
	}
	ok(c, gin.H{"deleted": true})
}

type checkCertificateRequest struct {
	ID  uint   `json:"id"`
	IDs []uint `json:"ids"`
	All bool   `json:"all"`
}

func (s *Server) checkCertificates(c *gin.Context) {
	var req checkCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求参数无效")
		return
	}
	if req.ID > 0 {
		cert, err := s.ssl.CheckOne(c.Request.Context(), req.ID, "manual")
		if err != nil {
			if isNotFound(err) {
				notFound(c, "证书监控不存在")
			} else if err.Error() == "该证书监控正在检测中" {
				conflict(c, err.Error())
			} else {
				serverError(c, err)
			}
			return
		}
		ok(c, certView(cert))
		return
	}
	if len(req.IDs) > 0 {
		result, err := s.ssl.CheckByIDs(c.Request.Context(), req.IDs, "manual")
		if err != nil {
			serverError(c, err)
			return
		}
		ok(c, result)
		return
	}
	if req.All {
		go s.ssl.CheckAll(context.Background(), "manual")
		c.JSON(http.StatusAccepted, response{Code: 0, Message: "已开始检测所有证书"})
		return
	}
	badRequest(c, "请指定要检测的证书")
}

func (s *Server) checkCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	cert, err := s.ssl.CheckOne(c.Request.Context(), id, "manual")
	if err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else if err.Error() == "该证书监控正在检测中" {
			conflict(c, err.Error())
		} else {
			serverError(c, err)
		}
		return
	}
	ok(c, certView(cert))
}

func (s *Server) applyCertificate(c *gin.Context) {
	var req acme.ApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "证书申请参数无效")
		return
	}
	order, err := s.acme.Apply(c.Request.Context(), req)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusAccepted, response{Code: 0, Message: "证书申请订单已创建", Data: orderView(order)})
}

func orderView(order *models.CertificateOrder) gin.H {
	var domains []string
	_ = json.Unmarshal([]byte(order.DomainsJSON), &domains)
	if domains == nil {
		domains = []string{}
	}
	return gin.H{
		"id": order.ID, "primary_domain": order.PrimaryDomain, "domains": domains,
		"challenge_type": order.ChallengeType, "dns_provider": order.DNSProvider,
		"key_type": order.KeyType, "email": order.Email, "staging": order.Staging,
		"auto_renew": order.AutoRenew, "status": order.Status, "attempts": order.Attempts,
		"max_attempts": order.MaxAttempts, "last_error": order.LastError, "logs": order.Logs,
		"cert_id": order.CertID, "renewal_of": order.RenewalOf, "not_before": order.NotBefore,
		"not_after": order.NotAfter, "next_retry_at": order.NextRetryAt, "started_at": order.StartedAt,
		"completed_at": order.CompletedAt, "created_at": order.CreatedAt, "updated_at": order.UpdatedAt,
	}
}

func (s *Server) renewCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	order, err := s.acme.RenewCertificate(c.Request.Context(), id)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusAccepted, response{Code: 0, Message: "续期订单已创建", Data: orderView(order)})
}

func (s *Server) deployCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	dir, err := s.certs.Deploy(c.Request.Context(), &cert)
	_ = s.db.Create(&models.MonitorLog{
		Kind: "certificate", TargetID: cert.ID, Target: cert.Domain, Action: "deploy",
		Status: map[bool]string{true: "success", false: "failed"}[err == nil],
		Message: func() string {
			if err != nil {
				return security.SanitizeText(err.Error(), 1000)
			}
			return "证书文件已部署"
		}(),
	}).Error
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	ok(c, gin.H{"deployed": true, "directory": dir})
}

func (s *Server) downloadCertificate(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	kind := strings.ToLower(c.DefaultQuery("type", "fullchain"))
	if kind == "privkey" {
		confirm := c.Query("confirm")
		if confirm != "1" && !strings.EqualFold(confirm, "true") {
			badRequest(c, "下载私钥必须显式确认")
			return
		}
	}
	var cert models.SSLCertificate
	if err := s.db.First(&cert, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "证书监控不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	file, err := s.certs.ReadFile(&cert, kind)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	_ = s.db.Create(&models.MonitorLog{
		Kind: "certificate", TargetID: cert.ID, Target: cert.Domain, Action: "download",
		Status: "success", Message: "下载证书文件: " + file.Name,
	}).Error
	filename := strings.ReplaceAll(cert.Domain, "*", "wildcard") + "-" + file.Name
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, file.ContentType, file.Data)
}

func (s *Server) listOrders(c *gin.Context) {
	orders, err := s.acme.Orders(100)
	if err != nil {
		serverError(c, err)
		return
	}
	items := make([]gin.H, 0, len(orders))
	for i := range orders {
		items = append(items, orderView(&orders[i]))
	}
	ok(c, items)
}

func (s *Server) retryOrder(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	if err := s.acme.ManualRetry(c.Request.Context(), id); err != nil {
		badRequest(c, err.Error())
		return
	}
	ok(c, gin.H{"retrying": true})
}

func (s *Server) listACMEAccounts(c *gin.Context) {
	var accounts []models.ACMEAccount
	if err := s.db.Order("id DESC").Find(&accounts).Error; err != nil {
		serverError(c, err)
		return
	}
	ok(c, accounts)
}
