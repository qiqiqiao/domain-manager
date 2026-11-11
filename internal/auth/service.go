package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials   = errors.New("用户名或密码错误")
	ErrAccountLocked        = errors.New("登录失败次数过多，请稍后再试")
	ErrInactive             = errors.New("账号已被禁用")
	ErrInvalidTOTP          = errors.New("动态验证码或恢复码无效")
	ErrTOTPChallengeExpired = errors.New("二次认证会话已失效，请重新登录")
	ErrTOTPNotEnabled       = errors.New("尚未启用二次认证")
	ErrTOTPAlreadyEnabled   = errors.New("二次认证已启用，请先关闭后再重新设置")
	ErrTOTPSetupMissing     = errors.New("请先生成二次认证密钥")
)

const (
	totpChallengeTTL      = 5 * time.Minute
	maxTOTPChallengeTries = 5
	recoveryCodeCount     = 10
)

// dummyPasswordHash is checked when the username does not exist so that the
// expensive bcrypt path has similar timing in both cases.
var dummyPasswordHash, _ = security.HashPassword("domain-manager-dummy-password")

// LoginResult describes either a completed password login or a login that is
// waiting for the TOTP second factor. No session is created until both factors
// succeed.
type LoginResult struct {
	User               *models.User
	Session            *security.Session
	Token              string
	RequiresTOTP       bool
	ChallengeToken     string
	ChallengeExpiresAt time.Time
}

type totpChallenge struct {
	UserID    uint
	Username  string
	LimitKey  string
	ExpiresAt time.Time
	Attempts  int
}

type Service struct {
	db       *gorm.DB
	settings *settings.Manager
	sessions *security.SessionManager
	cipher   *security.Cipher
	limiter  *security.LoginLimiter
	mu       sync.RWMutex

	challengeMu sync.Mutex
	challenges  map[string]*totpChallenge
}

func New(db *gorm.DB, st *settings.Manager, sessions *security.SessionManager, cipher *security.Cipher) *Service {
	s := &Service{
		db: db, settings: st, sessions: sessions, cipher: cipher,
		challenges: make(map[string]*totpChallenge),
	}
	s.limiter = security.NewLoginLimiter(st.Int("login_max_attempts"), 15*time.Minute, time.Duration(st.Int("login_lock_minutes"))*time.Minute)
	return s
}

func (s *Service) RefreshPolicy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limiter = security.NewLoginLimiter(s.settings.Int("login_max_attempts"), 15*time.Minute, time.Duration(s.settings.Int("login_lock_minutes"))*time.Minute)
	s.sessions.SetTTL(time.Duration(s.settings.Int("session_ttl_hours")) * time.Hour)
}

// Login verifies the password. When TOTP is enabled it returns a short-lived
// challenge instead of a session; the caller must then call CompleteTOTP.
func (s *Service) Login(username, password, ip, ua string) (*LoginResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	key := strings.ToLower(username) + "|" + ip
	if !s.limiter.Allowed(key) {
		return nil, ErrAccountLocked
	}
	var user models.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Do a real bcrypt comparison so a missing username is not
			// distinguishable from a wrong password through response timing.
			_ = security.CheckPassword(dummyPasswordHash, password)
			s.limiter.Fail(key)
			logger.L().Warn("管理员登录失败", "username", username, "ip", ip)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if !security.CheckPassword(user.PasswordHash, password) {
		s.limiter.Fail(key)
		user.FailedAttempts++
		// Locking is scoped to username+IP by the in-memory limiter. The
		// database counter is kept for auditing only, so one attacker cannot
		// lock the administrator out globally.
		_ = s.db.Model(&user).Update("failed_attempts", user.FailedAttempts).Error
		logger.L().Warn("管理员登录失败", "username", username, "ip", ip)
		return nil, ErrInvalidCredentials
	}
	if !user.Active {
		return nil, ErrInactive
	}
	if user.TOTPEnabled {
		token, expiresAt, err := s.issueTOTPChallenge(&user, key)
		if err != nil {
			return nil, err
		}
		logger.L().Info("管理员密码校验通过，等待二次认证", "username", username, "ip", ip)
		return &LoginResult{
			User: &user, RequiresTOTP: true,
			ChallengeToken: token, ChallengeExpiresAt: expiresAt,
		}, nil
	}
	session, token, err := s.finishLogin(&user, key, ip, ua, "password")
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: &user, Session: session, Token: token}, nil
}

// CompleteTOTP exchanges a pending login challenge plus a TOTP or recovery
// code for a real session.
func (s *Service) CompleteTOTP(challengeToken, code, ip, ua string) (*models.User, *security.Session, string, error) {
	challengeToken = strings.TrimSpace(challengeToken)
	if challengeToken == "" {
		return nil, nil, "", ErrTOTPChallengeExpired
	}
	challengeKey := security.HashToken(challengeToken)
	s.challengeMu.Lock()
	challenge, ok := s.challenges[challengeKey]
	if ok && time.Now().After(challenge.ExpiresAt) {
		delete(s.challenges, challengeKey)
		ok = false
	}
	if !ok {
		s.challengeMu.Unlock()
		return nil, nil, "", ErrTOTPChallengeExpired
	}
	challenge.Attempts++
	attempts := challenge.Attempts
	if attempts > maxTOTPChallengeTries {
		delete(s.challenges, challengeKey)
		s.challengeMu.Unlock()
		return nil, nil, "", ErrAccountLocked
	}
	limitKey := challenge.LimitKey
	userID := challenge.UserID
	username := challenge.Username
	s.challengeMu.Unlock()

	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		s.dropChallenge(challengeKey)
		return nil, nil, "", ErrTOTPChallengeExpired
	}
	if !user.Active {
		s.dropChallenge(challengeKey)
		return nil, nil, "", ErrInactive
	}
	if !user.TOTPEnabled {
		s.dropChallenge(challengeKey)
		return nil, nil, "", ErrTOTPNotEnabled
	}

	secret, err := s.decryptTOTPSecret(&user)
	if err != nil {
		s.dropChallenge(challengeKey)
		return nil, nil, "", err
	}
	now := time.Now()
	step, totpOK := security.VerifyTOTP(secret, code, now, 1)
	if totpOK && step <= user.TOTPLastUsedStep {
		// Reject a code that was already accepted in this or an earlier step.
		totpOK = false
	}
	method := "totp"
	if !totpOK {
		used, recoveryErr := s.consumeRecoveryCode(&user, code)
		if recoveryErr != nil {
			return nil, nil, "", recoveryErr
		}
		if used {
			method = "recovery_code"
		} else {
			s.limiter.Fail(limitKey)
			if attempts >= maxTOTPChallengeTries {
				s.dropChallenge(challengeKey)
			}
			logger.L().Warn("二次认证失败", "username", username, "ip", ip)
			if !s.limiter.Allowed(limitKey) {
				return nil, nil, "", ErrAccountLocked
			}
			return nil, nil, "", ErrInvalidTOTP
		}
	}

	updates := map[string]any{
		"last_login_at": now, "failed_attempts": 0, "locked_until": nil,
	}
	query := s.db.Model(&models.User{}).Where("id = ?", user.ID)
	if method == "totp" {
		updates["totp_last_used_step"] = step
		// Guard against two concurrent requests accepting the same time step.
		query = query.Where("totp_last_used_step < ?", step)
	}
	result := query.Updates(updates)
	if result.Error != nil {
		return nil, nil, "", result.Error
	}
	if result.RowsAffected == 0 {
		s.limiter.Fail(limitKey)
		return nil, nil, "", ErrInvalidTOTP
	}
	s.dropChallenge(challengeKey)
	s.limiter.Reset(limitKey)
	user.LastLoginAt = &now
	if method == "totp" {
		user.TOTPLastUsedStep = step
	}
	session, token, err := s.sessions.Create(user.ID, user.Username, ip, ua)
	if err != nil {
		return nil, nil, "", err
	}
	logger.L().Info("管理员登录成功", "username", user.Username, "ip", ip, "method", method)
	return &user, session, token, nil
}

func (s *Service) finishLogin(user *models.User, limitKey, ip, ua, method string) (*security.Session, string, error) {
	now := time.Now()
	if err := s.db.Model(user).Updates(map[string]any{
		"last_login_at": now, "failed_attempts": 0, "locked_until": nil,
	}).Error; err != nil {
		return nil, "", err
	}
	s.limiter.Reset(limitKey)
	user.LastLoginAt = &now
	session, token, err := s.sessions.Create(user.ID, user.Username, ip, ua)
	if err != nil {
		return nil, "", err
	}
	logger.L().Info("管理员登录成功", "username", user.Username, "ip", ip, "method", method)
	return session, token, nil
}

func (s *Service) issueTOTPChallenge(user *models.User, limitKey string) (string, time.Time, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(totpChallengeTTL)
	now := time.Now()
	s.challengeMu.Lock()
	for key, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, key)
		}
	}
	s.challenges[security.HashToken(token)] = &totpChallenge{
		UserID: user.ID, Username: user.Username, LimitKey: limitKey, ExpiresAt: expiresAt,
	}
	s.challengeMu.Unlock()
	return token, expiresAt, nil
}

func (s *Service) dropChallenge(key string) {
	s.challengeMu.Lock()
	delete(s.challenges, key)
	s.challengeMu.Unlock()
}

// SetupTOTP generates a new pending secret. TOTP is not activated until the
// user confirms a valid code through EnableTOTP.
func (s *Service) SetupTOTP(userID uint, password, issuer string) (string, string, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return "", "", err
	}
	if !security.CheckPassword(user.PasswordHash, password) {
		return "", "", errors.New("当前密码错误")
	}
	if user.TOTPEnabled {
		return "", "", ErrTOTPAlreadyEnabled
	}
	if s.cipher == nil {
		return "", "", errors.New("加密服务不可用")
	}
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	encrypted, err := s.cipher.Encrypt(secret)
	if err != nil {
		return "", "", err
	}
	if err := s.db.Model(&models.User{}).Where("id = ? AND totp_enabled = ?", user.ID, false).Updates(map[string]any{
		"totp_secret": encrypted, "totp_enabled": false,
		"totp_recovery_codes": "", "totp_last_used_step": 0,
	}).Error; err != nil {
		return "", "", err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(s.settings.Get("site_name"))
	}
	if issuer == "" {
		issuer = "Domain Manager"
	}
	logger.L().Info("管理员生成二次认证密钥", "username", user.Username)
	return secret, security.TOTPURL(issuer, user.Username, secret), nil
}

// EnableTOTP activates a pending secret and returns the recovery codes exactly
// once. Only their hashes are persisted.
func (s *Service) EnableTOTP(userID uint, code string) ([]string, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return nil, err
	}
	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}
	secret, err := s.decryptTOTPSecret(&user)
	if err != nil {
		return nil, err
	}
	if _, ok := security.VerifyTOTP(secret, code, time.Now(), 1); !ok {
		return nil, ErrInvalidTOTP
	}
	plain, hashes, err := security.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(hashes)
	if err != nil {
		return nil, err
	}
	result := s.db.Model(&models.User{}).Where("id = ? AND totp_enabled = ?", user.ID, false).Updates(map[string]any{
		"totp_enabled": true, "totp_recovery_codes": string(encoded), "totp_last_used_step": 0,
	})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, ErrTOTPAlreadyEnabled
	}
	logger.L().Info("管理员已启用二次认证", "username", user.Username)
	return plain, nil
}

func (s *Service) DisableTOTP(userID uint, password, code string) error {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return err
	}
	if !security.CheckPassword(user.PasswordHash, password) {
		return errors.New("当前密码错误")
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}
	if _, err := s.checkSecondFactor(&user, code); err != nil {
		return err
	}
	if err := s.db.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{
		"totp_secret": "", "totp_enabled": false,
		"totp_recovery_codes": "", "totp_last_used_step": 0,
	}).Error; err != nil {
		return err
	}
	logger.L().Info("管理员已关闭二次认证", "username", user.Username)
	return nil
}

// RegenerateRecoveryCodes replaces all recovery codes and returns the new
// plaintext list once.
func (s *Service) RegenerateRecoveryCodes(userID uint, password, code string) ([]string, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return nil, err
	}
	if !security.CheckPassword(user.PasswordHash, password) {
		return nil, errors.New("当前密码错误")
	}
	if !user.TOTPEnabled {
		return nil, ErrTOTPNotEnabled
	}
	if _, err := s.checkSecondFactor(&user, code); err != nil {
		return nil, err
	}
	plain, hashes, err := security.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(hashes)
	if err != nil {
		return nil, err
	}
	if err := s.db.Model(&models.User{}).Where("id = ?", user.ID).Update("totp_recovery_codes", string(encoded)).Error; err != nil {
		return nil, err
	}
	logger.L().Info("管理员重新生成二次认证恢复码", "username", user.Username)
	return plain, nil
}

func (s *Service) decryptTOTPSecret(user *models.User) (string, error) {
	if strings.TrimSpace(user.TOTPSecret) == "" {
		return "", ErrTOTPSetupMissing
	}
	if s.cipher == nil {
		return "", errors.New("加密服务不可用")
	}
	secret, err := s.cipher.Decrypt(user.TOTPSecret)
	if err != nil {
		return "", errors.New("读取二次认证密钥失败，请使用恢复码登录或重新配置")
	}
	return secret, nil
}

// checkSecondFactor accepts either a current TOTP code or a one-time recovery
// code. It returns true when a recovery code was consumed.
func (s *Service) checkSecondFactor(user *models.User, code string) (bool, error) {
	secret, err := s.decryptTOTPSecret(user)
	if err == nil {
		if _, ok := security.VerifyTOTP(secret, code, time.Now(), 1); ok {
			return false, nil
		}
	}
	used, err := s.consumeRecoveryCode(user, code)
	if err != nil {
		return false, err
	}
	if used {
		return true, nil
	}
	return false, ErrInvalidTOTP
}

func (s *Service) consumeRecoveryCode(user *models.User, code string) (bool, error) {
	hashes := decodeRecoveryCodes(user.TOTPRecoveryCodes)
	for index, hash := range hashes {
		if !security.RecoveryCodeMatches(hash, code) {
			continue
		}
		remaining := append(append([]string{}, hashes[:index]...), hashes[index+1:]...)
		encoded, err := json.Marshal(remaining)
		if err != nil {
			return false, err
		}
		if err := s.db.Model(user).Update("totp_recovery_codes", string(encoded)).Error; err != nil {
			return false, err
		}
		user.TOTPRecoveryCodes = string(encoded)
		return true, nil
	}
	return false, nil
}

func decodeRecoveryCodes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return nil
	}
	return hashes
}

func (s *Service) UserByToken(token string) (*models.User, *security.Session, error) {
	session, ok := s.sessions.Get(token)
	if !ok {
		return nil, nil, errors.New("会话已失效")
	}
	var user models.User
	if err := s.db.First(&user, session.UserID).Error; err != nil {
		return nil, nil, errors.New("用户不存在")
	}
	if !user.Active {
		return nil, nil, ErrInactive
	}
	return &user, session, nil
}

func (s *Service) Logout(token string) {
	s.sessions.Delete(token)
}

func (s *Service) ChangePassword(userID uint, current, next string) error {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return err
	}
	if !security.CheckPassword(user.PasswordHash, current) {
		return errors.New("当前密码错误")
	}
	if len(next) < 8 {
		return errors.New("新密码至少需要 8 个字符")
	}
	if current == next {
		return errors.New("新密码不能与当前密码相同")
	}
	hash, err := security.HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.db.Model(&user).Updates(map[string]any{
		"password_hash": hash, "must_change_password": false, "failed_attempts": 0, "locked_until": nil,
	}).Error; err != nil {
		return err
	}
	s.sessions.DeleteUser(user.ID)
	logger.L().Info("管理员密码已修改", "username", user.Username)
	return nil
}

func (s *Service) EnsureUser(userID uint) (*models.User, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("读取管理员失败: %w", err)
	}
	return &user, nil
}
