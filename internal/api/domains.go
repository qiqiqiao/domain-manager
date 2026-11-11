package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"domain-manager/internal/models"
	"domain-manager/internal/security"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var errDuplicateDomain = errors.New("域名已存在")

type createDomainRequest struct {
	Name           string `json:"name" binding:"required"`
	Notes          string `json:"notes"`
	ExpiresAt      string `json:"expires_at"`
	MonitorEnabled *bool  `json:"monitor_enabled"`
	AutoCheck      *bool  `json:"auto_check"`
}

func (s *Server) listDomains(c *gin.Context) {
	page, size := pageParams(c)
	query := s.db.Model(&models.Domain{})
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("name LIKE ? OR registrar LIKE ? OR notes LIKE ?", like, like, like)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if enabled := c.Query("monitor_enabled"); enabled != "" {
		if b, err := strconv.ParseBool(enabled); err == nil {
			query = query.Where("monitor_enabled = ?", b)
		}
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		serverError(c, err)
		return
	}
	var items []models.Domain
	if err := query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&items).Error; err != nil {
		serverError(c, err)
		return
	}
	for i := range items {
		if items[i].ExpiresAt != nil {
			items[i].DaysRemaining = computeDays(items[i].ExpiresAt)
		}
	}
	ok(c, paginated(items, total, page, size))
}

func (s *Server) getDomain(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var domain models.Domain
	if err := s.db.First(&domain, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "域名不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	if domain.ExpiresAt != nil {
		domain.DaysRemaining = computeDays(domain.ExpiresAt)
	}
	ok(c, domain)
}

func (s *Server) createDomain(c *gin.Context) {
	var req createDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请填写域名")
		return
	}
	name, err := security.NormalizeDomain(req.Name, false)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	if len(req.Notes) > 2000 {
		badRequest(c, "备注长度不能超过 2000 个字符")
		return
	}
	expires, err := parseDateIn(req.ExpiresAt, s.settings.Location())
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	enabled := true
	if req.MonitorEnabled != nil {
		enabled = *req.MonitorEnabled
	}
	domain, err := s.createDomainRecord(name, req.Notes, expires, enabled)
	if err != nil {
		if errors.Is(err, errDuplicateDomain) {
			conflict(c, err.Error())
		} else {
			serverError(c, err)
		}
		return
	}
	autoCheck := true
	if req.AutoCheck != nil {
		autoCheck = *req.AutoCheck
	}
	if autoCheck && enabled {
		go s.domains.CheckIDs(context.Background(), []uint{domain.ID}, "auto")
	}
	created(c, domain)
}

func (s *Server) createDomainRecord(name, notes string, expires *time.Time, enabled bool) (*models.Domain, error) {
	var existing int64
	if err := s.db.Model(&models.Domain{}).Where("name = ?", name).Count(&existing).Error; err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, errDuplicateDomain
	}
	status := models.DomainStatusPending
	source := "unknown"
	days := 0
	if expires != nil {
		days = security.DaysUntilIn(*expires, s.settings.Location())
		source = "manual"
		if days < 0 {
			status = models.DomainStatusExpired
		} else if days <= s.settings.Int("domain_warning_days") {
			status = models.DomainStatusExpiring
		} else {
			status = models.DomainStatusNormal
		}
	}
	domain := &models.Domain{
		Name: name, Notes: notes, ExpiresAt: expires, ExpirySource: source,
		ExpiryLocked: expires != nil, DaysRemaining: days, Status: status, MonitorEnabled: enabled,
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(domain).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return errDuplicateDomain
			}
			return err
		}
		cert := models.SSLCertificate{
			DomainID: &domain.ID, Domain: name, Port: 443, MonitorEnabled: enabled,
			Source: "monitor", Status: models.CertStatusPending, HTTPSStatus: "unknown",
		}
		return tx.Where("domain = ? AND port = ?", name, 443).FirstOrCreate(&cert).Error
	})
	if err != nil {
		return nil, err
	}
	return domain, nil
}

func (s *Server) updateDomain(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var domain models.Domain
	if err := s.db.First(&domain, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "域名不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	var req struct {
		Notes          *string `json:"notes"`
		ExpiresAt      *string `json:"expires_at"`
		ExpiryLocked   *bool   `json:"expiry_locked"`
		MonitorEnabled *bool   `json:"monitor_enabled"`
		Registrar      *string `json:"registrar"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请求参数无效")
		return
	}
	updates := map[string]any{}
	if req.Notes != nil {
		if len(*req.Notes) > 2000 {
			badRequest(c, "备注长度不能超过 2000 个字符")
			return
		}
		updates["notes"] = *req.Notes
	}
	if req.Registrar != nil && domain.ExpirySource != "rdap" && domain.ExpirySource != "whois" {
		updates["registrar"] = security.SanitizeText(*req.Registrar, 255)
	}
	if req.ExpiresAt != nil {
		value := strings.TrimSpace(*req.ExpiresAt)
		if value == "" {
			updates["expires_at"] = nil
			updates["expiry_locked"] = false
			updates["expiry_source"] = "unknown"
			updates["status"] = models.DomainStatusPending
			updates["days_remaining"] = 0
		} else {
			expires, err := parseDateIn(value, s.settings.Location())
			if err != nil || expires == nil {
				badRequest(c, "到期日期格式无效")
				return
			}
			days := security.DaysUntilIn(*expires, s.settings.Location())
			status := models.DomainStatusNormal
			if days < 0 {
				status = models.DomainStatusExpired
			} else if days <= s.settings.Int("domain_warning_days") {
				status = models.DomainStatusExpiring
			}
			updates["expires_at"] = *expires
			updates["expiry_locked"] = true
			updates["expiry_source"] = "manual"
			updates["days_remaining"] = days
			updates["status"] = status
			updates["last_error"] = ""
		}
	} else if req.ExpiryLocked != nil && !*req.ExpiryLocked {
		updates["expiry_locked"] = false
	}
	if req.MonitorEnabled != nil {
		updates["monitor_enabled"] = *req.MonitorEnabled
		_ = s.db.Model(&models.SSLCertificate{}).Where("domain_id = ?", domain.ID).Update("monitor_enabled", *req.MonitorEnabled).Error
	}
	if len(updates) > 0 {
		if err := s.db.Model(&domain).Updates(updates).Error; err != nil {
			serverError(c, err)
			return
		}
	}
	_ = s.db.First(&domain, id).Error
	if domain.ExpiresAt != nil {
		domain.DaysRemaining = computeDays(domain.ExpiresAt)
	}
	ok(c, domain)
}

func (s *Server) deleteDomain(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	var domain models.Domain
	if err := s.db.First(&domain, id).Error; err != nil {
		if isNotFound(err) {
			notFound(c, "域名不存在")
		} else {
			serverError(c, err)
		}
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("domain_id = ? AND managed = ?", id, false).Delete(&models.SSLCertificate{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.SSLCertificate{}).Where("domain_id = ?", id).Update("domain_id", nil).Error; err != nil {
			return err
		}
		return tx.Delete(&domain).Error
	}); err != nil {
		serverError(c, err)
		return
	}
	ok(c, gin.H{"deleted": true})
}

func (s *Server) checkDomain(c *gin.Context) {
	id, valid := parseUintParam(c, "id")
	if !valid {
		return
	}
	domain, err := s.domains.CheckOne(c.Request.Context(), id, "manual")
	if err != nil {
		if isNotFound(err) {
			notFound(c, "域名不存在")
		} else if err.Error() == "该域名正在检测中" {
			conflict(c, err.Error())
		} else {
			serverError(c, err)
		}
		return
	}
	ok(c, domain)
}

func (s *Server) checkAllDomains(c *gin.Context) {
	go s.domains.CheckAll(context.Background(), "manual")
	c.JSON(http.StatusAccepted, response{Code: 0, Message: "已开始检测所有域名"})
}

type importRow struct {
	Domain    string
	ExpiresAt string
	Notes     string
}

func (s *Server) importDomains(c *gin.Context) {
	rows, autoCheck, err := s.readImport(c)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	if len(rows) == 0 {
		badRequest(c, "导入内容为空")
		return
	}
	if len(rows) > 1000 {
		badRequest(c, "单次最多导入 1000 个域名")
		return
	}
	imported := 0
	skipped := 0
	invalid := 0
	var errs []string
	var ids []uint
	seen := map[string]bool{}
	for _, row := range rows {
		name, err := security.NormalizeDomain(row.Domain, false)
		if err != nil {
			invalid++
			if len(errs) < 20 {
				errs = append(errs, fmt.Sprintf("%s: %s", row.Domain, err))
			}
			continue
		}
		if seen[name] {
			skipped++
			continue
		}
		seen[name] = true
		expires, err := parseDateIn(row.ExpiresAt, s.settings.Location())
		if err != nil {
			invalid++
			if len(errs) < 20 {
				errs = append(errs, fmt.Sprintf("%s: 到期日期格式无效", row.Domain))
			}
			continue
		}
		domain, err := s.createDomainRecord(name, row.Notes, expires, true)
		if err != nil {
			if errors.Is(err, errDuplicateDomain) {
				skipped++
			} else {
				invalid++
				if len(errs) < 20 {
					errs = append(errs, fmt.Sprintf("%s: 保存失败", name))
				}
			}
			continue
		}
		imported++
		ids = append(ids, domain.ID)
	}
	if autoCheck && len(ids) > 0 {
		go s.domains.CheckIDs(context.Background(), ids, "import")
	}
	ok(c, gin.H{"imported": imported, "skipped": skipped, "invalid": invalid, "errors": errs})
}

func (s *Server) readImport(c *gin.Context) ([]importRow, bool, error) {
	autoCheck := true
	if value := c.PostForm("auto_check"); value != "" {
		autoCheck, _ = strconv.ParseBool(value)
	}
	contentType := c.ContentType()
	if strings.HasPrefix(contentType, "application/json") {
		var req struct {
			Domains   []string `json:"domains"`
			AutoCheck *bool    `json:"auto_check"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			return nil, autoCheck, errors.New("JSON 导入格式无效")
		}
		if req.AutoCheck != nil {
			autoCheck = *req.AutoCheck
		}
		rows := make([]importRow, 0, len(req.Domains))
		for _, d := range req.Domains {
			rows = append(rows, importRow{Domain: d})
		}
		return rows, autoCheck, nil
	}
	var data []byte
	if strings.HasPrefix(contentType, "multipart/form-data") {
		file, err := c.FormFile("file")
		if err == nil {
			if err := validateImportFile(file); err != nil {
				return nil, autoCheck, err
			}
			f, err := file.Open()
			if err != nil {
				return nil, autoCheck, errors.New("读取上传文件失败")
			}
			defer f.Close()
			data, err = io.ReadAll(io.LimitReader(f, 2<<20+1))
			if err != nil {
				return nil, autoCheck, errors.New("读取上传文件失败")
			}
			if len(data) > 2<<20 {
				return nil, autoCheck, errors.New("导入文件不能超过 2MB")
			}
		} else {
			data = []byte(c.PostForm("text"))
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, 2<<20+1))
		if err != nil {
			return nil, autoCheck, errors.New("读取导入内容失败")
		}
		if len(body) > 2<<20 {
			return nil, autoCheck, errors.New("导入内容不能超过 2MB")
		}
		data = body
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, autoCheck, errors.New("导入内容为空")
	}
	rows, err := parseImportCSV(data)
	return rows, autoCheck, err
}

func validateImportFile(header *multipart.FileHeader) error {
	if header.Size > 2<<20 {
		return errors.New("导入文件不能超过 2MB")
	}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".csv" && ext != ".txt" {
		return errors.New("仅支持 CSV 或 TXT 文件")
	}
	return nil
}

func parseImportCSV(data []byte) ([]importRow, error) {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, errors.New("CSV 格式错误")
	}
	var rows []importRow
	for i, record := range records {
		if len(record) == 0 {
			continue
		}
		first := strings.TrimSpace(strings.TrimPrefix(record[0], "\ufeff"))
		if first == "" || strings.HasPrefix(first, "#") {
			continue
		}
		if i == 0 && strings.EqualFold(first, "domain") {
			continue
		}
		row := importRow{Domain: first}
		if len(record) > 1 {
			row.ExpiresAt = strings.TrimSpace(record[1])
		}
		if len(record) > 2 {
			row.Notes = security.TruncateRunes(strings.TrimSpace(record[2]), 2000)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
