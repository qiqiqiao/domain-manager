package api

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"domain-manager/internal/acme"
	"domain-manager/internal/auth"
	"domain-manager/internal/certificate"
	"domain-manager/internal/config"
	"domain-manager/internal/logger"
	"domain-manager/internal/monitor"
	"domain-manager/internal/notification"
	"domain-manager/internal/scheduler"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"
	"domain-manager/web"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Server struct {
	cfg       *config.Config
	db        *gorm.DB
	settings  *settings.Manager
	auth      *auth.Service
	sessions  *security.SessionManager
	domains   *monitor.DomainService
	ssl       *monitor.SSLService
	certs     *certificate.Service
	acme      *acme.Service
	notifier  *notification.Service
	scheduler *scheduler.Scheduler
	cipher    *security.Cipher
	dist      fs.FS
	startedAt time.Time
	version   string
}

type Options struct {
	Config    *config.Config
	DB        *gorm.DB
	Settings  *settings.Manager
	Auth      *auth.Service
	Sessions  *security.SessionManager
	Domains   *monitor.DomainService
	SSL       *monitor.SSLService
	Certs     *certificate.Service
	ACME      *acme.Service
	Notifier  *notification.Service
	Scheduler *scheduler.Scheduler
	Cipher    *security.Cipher
	Version   string
}

func New(opts Options) (*Server, error) {
	dist, err := web.FS()
	if err != nil {
		return nil, fmt.Errorf("加载前端静态资源失败: %w", err)
	}
	return &Server{
		cfg: opts.Config, db: opts.DB, settings: opts.Settings, auth: opts.Auth,
		sessions: opts.Sessions, domains: opts.Domains, ssl: opts.SSL, certs: opts.Certs,
		acme: opts.ACME, notifier: opts.Notifier, scheduler: opts.Scheduler, cipher: opts.Cipher,
		dist: dist, startedAt: time.Now(), version: opts.Version,
	}, nil
}

func (s *Server) Router() *gin.Engine {
	gin.SetMode(s.cfg.Server.Mode)
	r := gin.New()
	r.HandleMethodNotAllowed = true
	r.MaxMultipartMemory = 32 << 20
	if len(s.cfg.Server.TrustedProxies) > 0 {
		_ = r.SetTrustedProxies(s.cfg.Server.TrustedProxies)
	} else {
		_ = r.SetTrustedProxies(nil)
	}
	r.Use(gin.Recovery())
	r.Use(s.requestID())
	r.Use(s.securityHeaders())
	r.Use(s.accessLog())
	r.Use(s.bodyLimit(int64(s.cfg.Server.MaxUploadMB) << 20))

	r.GET("/health", func(c *gin.Context) {
		status := "ok"
		code := http.StatusOK
		if sqlDB, err := s.db.DB(); err != nil {
			status = "database_error"
			code = http.StatusServiceUnavailable
		} else if err := sqlDB.PingContext(c.Request.Context()); err != nil {
			status = "database_error"
			code = http.StatusServiceUnavailable
		}
		c.JSON(code, gin.H{"status": status, "version": s.version, "time": time.Now().Format(time.RFC3339)})
	})

	v1 := r.Group("/api/v1")
	v1.POST("/auth/login", s.login)
	v1.POST("/auth/login/totp", s.loginTOTP)

	authorized := v1.Group("")
	authorized.Use(s.requireAuth())
	authorized.Use(s.csrfGuard())
	{
		authorized.POST("/auth/logout", s.logout)
		authorized.GET("/auth/me", s.me)
		authorized.PUT("/auth/password", s.changePassword)
		authorized.POST("/auth/totp/setup", s.setupTOTP)
		authorized.POST("/auth/totp/enable", s.enableTOTP)
		authorized.POST("/auth/totp/disable", s.disableTOTP)
		authorized.POST("/auth/totp/recovery-codes", s.regenerateTOTPRecoveryCodes)

		authorized.GET("/dashboard", s.dashboard)

		authorized.GET("/domains", s.listDomains)
		authorized.POST("/domains", s.createDomain)
		authorized.POST("/domains/import", s.importDomains)
		authorized.POST("/domains/check-all", s.checkAllDomains)
		authorized.GET("/domains/:id", s.getDomain)
		authorized.PUT("/domains/:id", s.updateDomain)
		authorized.DELETE("/domains/:id", s.deleteDomain)
		authorized.POST("/domains/:id/check", s.checkDomain)

		authorized.GET("/certificates", s.listCertificates)
		authorized.POST("/certificates", s.createCertificate)
		authorized.POST("/certificates/check", s.checkCertificates)
		authorized.POST("/certificates/apply", s.applyCertificate)
		authorized.GET("/certificates/:id", s.getCertificate)
		authorized.PUT("/certificates/:id", s.updateCertificate)
		authorized.DELETE("/certificates/:id", s.deleteCertificate)
		authorized.POST("/certificates/:id/check", s.checkCertificate)
		authorized.POST("/certificates/:id/renew", s.renewCertificate)
		authorized.POST("/certificates/:id/deploy", s.deployCertificate)
		authorized.GET("/certificates/:id/download", s.downloadCertificate)

		authorized.GET("/notifications", s.listNotifications)
		authorized.POST("/notifications", s.createNotification)
		authorized.PUT("/notifications/:id", s.updateNotification)
		authorized.DELETE("/notifications/:id", s.deleteNotification)
		authorized.POST("/notifications/:id/test", s.testNotification)
		authorized.GET("/notification-rules", s.listRules)
		authorized.PUT("/notification-rules", s.updateRules)

		authorized.GET("/logs/monitor", s.listMonitorLogs)
		authorized.GET("/logs/notification", s.listNotificationLogs)

		authorized.GET("/settings", s.getSettings)
		authorized.PUT("/settings", s.updateSettings)

		authorized.POST("/system/backup", s.backup)
		authorized.POST("/system/restore", s.restore)
		authorized.GET("/system/status", s.systemStatus)

		authorized.GET("/orders", s.listOrders)
		authorized.POST("/orders/:id/retry", s.retryOrder)
		authorized.GET("/acme/accounts", s.listACMEAccounts)

		authorized.GET("/jobs", s.listJobs)
		authorized.POST("/jobs/:key/run", s.runJob)
		authorized.GET("/jobs/runs", s.listJobRuns)
	}

	s.registerStatic(r)
	return r
}

func (s *Server) requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		id := hex.EncodeToString(buf)
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

func (s *Server) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Cache-Control", "no-store")
		}
		c.Next()
	}
}

func (s *Server) accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			return
		}
		logger.L().Info("http_request",
			"method", c.Request.Method, "path", c.Request.URL.Path, "status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(), "ip", c.ClientIP(),
			"request_id", c.GetString("request_id"))
	}
}

func (s *Server) bodyLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if max > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		}
		c.Next()
	}
}

type staticAsset struct {
	data        []byte
	compressed  []byte
	contentType string
}

func (s *Server) registerStatic(r *gin.Engine) {
	var cache sync.Map // name -> *staticAsset
	load := func(name string) (*staticAsset, error) {
		if value, ok := cache.Load(name); ok {
			return value.(*staticAsset), nil
		}
		data, err := fs.ReadFile(s.dist, name)
		if err != nil {
			return nil, err
		}
		asset := &staticAsset{data: data, contentType: contentType(name)}
		if compressible(name) {
			var buf bytes.Buffer
			gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			if err == nil {
				_, _ = gz.Write(data)
				if gz.Close() == nil && buf.Len() < len(data) {
					asset.compressed = buf.Bytes()
				}
			}
		}
		cache.Store(name, asset)
		return asset, nil
	}
	serve := func(c *gin.Context, name, cacheControl string) bool {
		asset, err := load(name)
		if err != nil {
			return false
		}
		if cacheControl != "" {
			c.Header("Cache-Control", cacheControl)
		}
		c.Header("Vary", "Accept-Encoding")
		if asset.compressed != nil && strings.Contains(strings.ToLower(c.GetHeader("Accept-Encoding")), "gzip") {
			c.Header("Content-Encoding", "gzip")
			c.Data(http.StatusOK, asset.contentType, asset.compressed)
			return true
		}
		c.Data(http.StatusOK, asset.contentType, asset.data)
		return true
	}
	serveIndex := func(c *gin.Context) {
		if !serve(c, "index.html", "no-cache") {
			c.String(http.StatusInternalServerError, "前端资源未嵌入")
		}
	}
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/health" {
			fail(c, http.StatusNotFound, 404, "接口不存在")
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			fail(c, http.StatusMethodNotAllowed, 405, "请求方法不允许")
			return
		}
		requestPath := strings.TrimPrefix(path.Clean("/"+c.Request.URL.Path), "/")
		if requestPath == "" || requestPath == "." {
			serveIndex(c)
			return
		}
		if strings.Contains(requestPath, "..") {
			fail(c, http.StatusBadRequest, 400, "路径非法")
			return
		}
		info, err := fs.Stat(s.dist, requestPath)
		if err == nil && !info.IsDir() {
			cacheControl := ""
			if strings.HasPrefix(requestPath, "assets/") {
				cacheControl = "public, max-age=31536000, immutable"
			}
			if serve(c, requestPath, cacheControl) {
				return
			}
			serveIndex(c)
			return
		}
		if strings.Contains(path.Base(requestPath), ".") {
			fail(c, http.StatusNotFound, 404, "资源不存在")
			return
		}
		serveIndex(c)
	})
}

func compressible(name string) bool {
	switch {
	case strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".css"), strings.HasSuffix(name, ".html"),
		strings.HasSuffix(name, ".json"), strings.HasSuffix(name, ".svg"), strings.HasSuffix(name, ".txt"):
		return true
	default:
		return false
	}
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"), strings.HasSuffix(name, ".htm"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".mjs"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(name, ".json"), strings.HasSuffix(name, ".webmanifest"):
		return "application/json"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(name, ".woff"):
		return "font/woff"
	case strings.HasSuffix(name, ".txt"):
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
