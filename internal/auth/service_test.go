package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"
)

func newAuthService(t *testing.T) (*Service, uint) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := settings.New(db)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	hash, err := security.HashPassword("CorrectPassword123!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user := models.User{Username: "admin", PasswordHash: hash, Role: "admin", Active: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessions := security.NewSessionManager(time.Hour)
	cipher, err := security.LoadOrCreateCipher(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return New(db, st, sessions, cipher), user.ID
}

func TestLoginLockIsScopedToUsernameAndIP(t *testing.T) {
	svc, userID := newAuthService(t)
	for i := 0; i < 5; i++ {
		if _, err := svc.Login("admin", "wrong", "192.0.2.1", "test"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d error = %v", i, err)
		}
	}
	if _, err := svc.Login("admin", "CorrectPassword123!", "192.0.2.1", "test"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("same IP should be locked, got %v", err)
	}
	// A different source IP must still be able to log in. The old behavior
	// locked the database account globally.
	result, err := svc.Login("admin", "CorrectPassword123!", "192.0.2.2", "test")
	if err != nil {
		t.Fatalf("different IP login: %v", err)
	}
	if result.Session == nil || result.Token == "" {
		t.Fatal("expected a completed password-only login")
	}
	var user models.User
	if err := svc.db.First(&user, userID).Error; err != nil {
		t.Fatalf("read user: %v", err)
	}
	if user.LockedUntil != nil {
		t.Fatalf("database account lock should not be set: %v", user.LockedUntil)
	}
}

func TestUnknownUsernameGetsSameRateLimit(t *testing.T) {
	svc, _ := newAuthService(t)
	for i := 0; i < 5; i++ {
		if _, err := svc.Login("nobody", "wrong", "198.51.100.9", "test"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d error = %v", i, err)
		}
	}
	if _, err := svc.Login("nobody", "wrong", "198.51.100.9", "test"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("unknown username should also be rate limited, got %v", err)
	}
}

func TestTOTPLoginAndRecoveryCode(t *testing.T) {
	svc, userID := newAuthService(t)
	secret, otpauthURL, err := svc.SetupTOTP(userID, "CorrectPassword123!", "Domain Manager Test")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	if secret == "" || otpauthURL == "" {
		t.Fatal("setup returned empty secret or otpauth URL")
	}
	code, err := security.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	codes, err := svc.EnableTOTP(userID, code)
	if err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("recovery code count = %d", len(codes))
	}

	result, err := svc.Login("admin", "CorrectPassword123!", "203.0.113.10", "test")
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	if !result.RequiresTOTP || result.Session != nil || result.ChallengeToken == "" {
		t.Fatalf("expected pending TOTP challenge, got %+v", result)
	}
	if _, _, _, err := svc.CompleteTOTP(result.ChallengeToken, "000000", "203.0.113.10", "test"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("wrong totp error = %v", err)
	}
	// The challenge remains valid after a single wrong code.
	nextCode, err := security.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate next code: %v", err)
	}
	user, session, token, err := svc.CompleteTOTP(result.ChallengeToken, nextCode, "203.0.113.10", "test")
	if err != nil {
		t.Fatalf("complete totp: %v", err)
	}
	if user.TOTPEnabled != true || session == nil || token == "" {
		t.Fatal("TOTP login did not create a session")
	}
	// Reusing the same challenge or code must fail.
	if _, _, _, err := svc.CompleteTOTP(result.ChallengeToken, nextCode, "203.0.113.10", "test"); !errors.Is(err, ErrTOTPChallengeExpired) {
		t.Fatalf("reused challenge error = %v", err)
	}

	// A recovery code works once and is removed afterwards.
	result, err = svc.Login("admin", "CorrectPassword123!", "203.0.113.11", "test")
	if err != nil || !result.RequiresTOTP {
		t.Fatalf("second password login: %v %+v", err, result)
	}
	if _, _, _, err := svc.CompleteTOTP(result.ChallengeToken, codes[0], "203.0.113.11", "test"); err != nil {
		t.Fatalf("recovery code login: %v", err)
	}
	result, err = svc.Login("admin", "CorrectPassword123!", "203.0.113.12", "test")
	if err != nil || !result.RequiresTOTP {
		t.Fatalf("third password login: %v %+v", err, result)
	}
	if _, _, _, err := svc.CompleteTOTP(result.ChallengeToken, codes[0], "203.0.113.12", "test"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("reused recovery code error = %v", err)
	}
}

func TestDisableTOTPRequiresPasswordAndCode(t *testing.T) {
	svc, userID := newAuthService(t)
	secret, _, err := svc.SetupTOTP(userID, "CorrectPassword123!", "")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, _ := security.GenerateTOTPCode(secret, time.Now())
	if _, err := svc.EnableTOTP(userID, code); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	code, _ = security.GenerateTOTPCode(secret, time.Now())
	if err := svc.DisableTOTP(userID, "wrong", code); err == nil {
		t.Fatal("disable with wrong password should fail")
	}
	if err := svc.DisableTOTP(userID, "CorrectPassword123!", "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("disable with wrong code error = %v", err)
	}
	if err := svc.DisableTOTP(userID, "CorrectPassword123!", code); err != nil {
		t.Fatalf("disable totp: %v", err)
	}
}
