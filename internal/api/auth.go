package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"domain-manager/internal/auth"
	"domain-manager/internal/models"
	"domain-manager/internal/security"

	"github.com/gin-gonic/gin"
)

const sessionCookie = "dm_session"

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type totpLoginRequest struct {
	ChallengeToken string `json:"challenge_token" binding:"required"`
	Code           string `json:"code" binding:"required"`
}

type totpSetupRequest struct {
	Password string `json:"password" binding:"required"`
}

type totpEnableRequest struct {
	Code string `json:"code" binding:"required"`
}

type totpSecurityRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

func (s *Server) login(c *gin.Context) {
	if c.Request.ContentLength > 8192 {
		fail(c, http.StatusRequestEntityTooLarge, 413, "登录请求体过大")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8192)
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "用户名和密码不能为空")
		return
	}
	if len(req.Username) > 64 || len(req.Password) > 512 {
		badRequest(c, "用户名或密码过长")
		return
	}
	result, err := s.auth.Login(req.Username, req.Password, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			fail(c, http.StatusTooManyRequests, 429, err.Error())
		case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInactive):
			fail(c, http.StatusUnauthorized, 401, "用户名或密码错误")
		default:
			serverError(c, err)
		}
		return
	}
	if result.RequiresTOTP {
		ok(c, gin.H{
			"totp_required": true, "challenge_token": result.ChallengeToken,
			"expires_at": result.ChallengeExpiresAt,
		})
		return
	}
	s.setSessionCookie(c, result.Token, result.Session.ExpiresAt)
	ok(c, gin.H{
		"user": result.User, "csrf_token": result.Session.CSRFToken, "expires_at": result.Session.ExpiresAt,
		"must_change_password": result.User.MustChangePassword, "totp_required": false,
	})
}

func (s *Server) loginTOTP(c *gin.Context) {
	if c.Request.ContentLength > 8192 {
		fail(c, http.StatusRequestEntityTooLarge, 413, "登录请求体过大")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8192)
	var req totpLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请填写二次认证验证码")
		return
	}
	if len(req.ChallengeToken) > 512 || len(req.Code) > 64 {
		badRequest(c, "二次认证参数无效")
		return
	}
	user, session, token, err := s.auth.CompleteTOTP(req.ChallengeToken, req.Code, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			fail(c, http.StatusTooManyRequests, 429, err.Error())
		case errors.Is(err, auth.ErrTOTPChallengeExpired):
			fail(c, http.StatusUnauthorized, 401, err.Error())
		case errors.Is(err, auth.ErrInvalidTOTP), errors.Is(err, auth.ErrInactive), errors.Is(err, auth.ErrTOTPNotEnabled):
			fail(c, http.StatusUnauthorized, 401, "动态验证码或恢复码无效")
		default:
			serverError(c, err)
		}
		return
	}
	s.setSessionCookie(c, token, session.ExpiresAt)
	ok(c, gin.H{
		"user": user, "csrf_token": session.CSRFToken, "expires_at": session.ExpiresAt,
		"must_change_password": user.MustChangePassword, "totp_required": false,
	})
}

func (s *Server) setupTOTP(c *gin.Context) {
	var req totpSetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请输入当前密码")
		return
	}
	if len(req.Password) > 512 {
		badRequest(c, "密码过长")
		return
	}
	user := c.MustGet("user").(*models.User)
	secret, otpauthURL, err := s.auth.SetupTOTP(user.ID, req.Password, s.settings.Get("site_name"))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
			conflict(c, err.Error())
		default:
			badRequest(c, err.Error())
		}
		return
	}
	ok(c, gin.H{"secret": secret, "otpauth_url": otpauthURL, "account": user.Username})
}

func (s *Server) enableTOTP(c *gin.Context) {
	var req totpEnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请输入身份验证器生成的动态验证码")
		return
	}
	if len(req.Code) > 64 {
		badRequest(c, "验证码过长")
		return
	}
	user := c.MustGet("user").(*models.User)
	codes, err := s.auth.EnableTOTP(user.ID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
			conflict(c, err.Error())
		case errors.Is(err, auth.ErrTOTPSetupMissing), errors.Is(err, auth.ErrInvalidTOTP):
			badRequest(c, err.Error())
		default:
			serverError(c, err)
		}
		return
	}
	ok(c, gin.H{"enabled": true, "recovery_codes": codes})
}

func (s *Server) disableTOTP(c *gin.Context) {
	var req totpSecurityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请输入当前密码和动态验证码或恢复码")
		return
	}
	if len(req.Password) > 512 || len(req.Code) > 64 {
		badRequest(c, "参数无效")
		return
	}
	user := c.MustGet("user").(*models.User)
	if err := s.auth.DisableTOTP(user.ID, req.Password, req.Code); err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPNotEnabled):
			conflict(c, err.Error())
		default:
			badRequest(c, err.Error())
		}
		return
	}
	ok(c, gin.H{"disabled": true})
}

func (s *Server) regenerateTOTPRecoveryCodes(c *gin.Context) {
	var req totpSecurityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请输入当前密码和动态验证码或恢复码")
		return
	}
	if len(req.Password) > 512 || len(req.Code) > 64 {
		badRequest(c, "参数无效")
		return
	}
	user := c.MustGet("user").(*models.User)
	codes, err := s.auth.RegenerateRecoveryCodes(user.ID, req.Password, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPNotEnabled):
			conflict(c, err.Error())
		default:
			badRequest(c, err.Error())
		}
		return
	}
	ok(c, gin.H{"recovery_codes": codes})
}

func (s *Server) logout(c *gin.Context) {
	if token := s.tokenFromRequest(c); token != "" {
		s.auth.Logout(token)
	}
	s.clearSessionCookie(c)
	ok(c, gin.H{"logged_out": true})
}

func (s *Server) me(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	session := c.MustGet("session").(*security.Session)
	ok(c, gin.H{
		"user": user, "csrf_token": session.CSRFToken, "expires_at": session.ExpiresAt,
	})
}

type passwordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (s *Server) changePassword(c *gin.Context) {
	var req passwordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "请填写当前密码和新密码")
		return
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > 128 {
		badRequest(c, "新密码长度必须为 8-128 个字符")
		return
	}
	user := c.MustGet("user").(*models.User)
	if err := s.auth.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		badRequest(c, err.Error())
		return
	}
	s.clearSessionCookie(c)
	ok(c, gin.H{"changed": true, "reauth_required": true})
}

func (s *Server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := s.tokenFromRequest(c)
		if token == "" {
			fail(c, http.StatusUnauthorized, 401, "请先登录")
			return
		}
		user, session, err := s.auth.UserByToken(token)
		if err != nil {
			s.clearSessionCookie(c)
			fail(c, http.StatusUnauthorized, 401, "登录状态已失效，请重新登录")
			return
		}
		if user.Role != "admin" {
			fail(c, http.StatusForbidden, 403, "当前账号没有管理权限")
			return
		}
		if user.MustChangePassword && !passwordChangePath(c) {
			fail(c, http.StatusForbidden, 403, "首次登录必须修改密码后才能使用其他功能")
			return
		}
		c.Set("user", user)
		c.Set("session", session)
		c.Set("token", token)
		c.Next()
	}
}

// passwordChangePath lists the only endpoints an account with the initial
// password may call. Keeping this in the middleware makes the restriction
// effective even when the web UI is bypassed.
func passwordChangePath(c *gin.Context) bool {
	path := c.Request.URL.Path
	switch path {
	case "/api/v1/auth/me":
		return c.Request.Method == http.MethodGet
	case "/api/v1/auth/password":
		return c.Request.Method == http.MethodPut
	case "/api/v1/auth/logout":
		return c.Request.Method == http.MethodPost
	}
	return false
}

func (s *Server) csrfGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		session := c.MustGet("session").(*security.Session)
		header := c.GetHeader("X-CSRF-Token")
		if header == "" || !security.ConstantEqual(header, session.CSRFToken) {
			fail(c, http.StatusForbidden, 403, "CSRF 校验失败，请刷新页面重试")
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !s.originAllowed(c, parsed) {
				fail(c, http.StatusForbidden, 403, "请求来源校验失败")
				return
			}
		}
		c.Next()
	}
}

func (s *Server) originAllowed(c *gin.Context, origin *url.URL) bool {
	if origin == nil || origin.Host == "" {
		return false
	}
	if strings.EqualFold(origin.Host, c.Request.Host) {
		return true
	}
	for _, key := range []string{"public_url", "site_url"} {
		raw := strings.TrimSpace(s.settings.Get(key))
		if raw == "" {
			continue
		}
		allowed, err := url.Parse(raw)
		if err != nil || allowed.Host == "" {
			continue
		}
		if strings.EqualFold(allowed.Host, origin.Host) &&
			strings.EqualFold(allowed.Scheme, origin.Scheme) {
			return true
		}
	}
	return false
}

func (s *Server) tokenFromRequest(c *gin.Context) string {
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	token, _ := c.Cookie(sessionCookie)
	return token
}

func (s *Server) setSessionCookie(c *gin.Context, token string, expires time.Time) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()),
		HttpOnly: true, Secure: s.cfg.Server.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
		HttpOnly: true, Secure: s.cfg.Server.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}
