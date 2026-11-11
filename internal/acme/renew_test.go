package acme

import (
	"path/filepath"
	"testing"
	"time"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/settings"
)

func renewalTestService(t *testing.T) (*Service, *models.CertificateOrder) {
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
	source := models.CertificateOrder{
		PrimaryDomain: "example.com", DomainsJSON: `["example.com"]`,
		ChallengeType: "http-01", Email: "a@example.com", Status: "valid", MaxAttempts: 3,
	}
	if err := db.Create(&source).Error; err != nil {
		t.Fatalf("create source: %v", err)
	}
	return NewService(db, st, nil, nil, nil, dir), &source
}

func createRenewal(t *testing.T, svc *Service, sourceID uint, status string, attempts int, updated time.Time) {
	t.Helper()
	order := models.CertificateOrder{
		PrimaryDomain: "example.com", DomainsJSON: `["example.com"]`,
		ChallengeType: "http-01", Email: "a@example.com", Status: status,
		Attempts: attempts, MaxAttempts: 3, RenewalOf: &sourceID,
	}
	if err := svc.db.Create(&order).Error; err != nil {
		t.Fatalf("create renewal: %v", err)
	}
	if err := svc.db.Model(&models.CertificateOrder{}).Where("id = ?", order.ID).
		UpdateColumn("updated_at", updated).Error; err != nil {
		t.Fatalf("age renewal: %v", err)
	}
}

func TestExhaustedRenewalOnlyBlocksDuringCooldown(t *testing.T) {
	svc, source := renewalTestService(t)
	createRenewal(t, svc, source.ID, "failed", 3, time.Now().Add(-25*time.Hour))
	blocked, err := svc.hasActiveRenewal(source.ID, true)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if blocked {
		t.Fatal("an exhausted failed order older than the cooldown must not block renewal forever")
	}

	createRenewal(t, svc, source.ID, "failed", 3, time.Now().Add(-time.Hour))
	blocked, err = svc.hasActiveRenewal(source.ID, true)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !blocked {
		t.Fatal("recently exhausted order should block during the cooldown")
	}
}

func TestRetryingAndPendingRenewalsBlock(t *testing.T) {
	svc, source := renewalTestService(t)
	createRenewal(t, svc, source.ID, "failed", 1, time.Now().Add(-72*time.Hour))
	blocked, err := svc.hasActiveRenewal(source.ID, true)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !blocked {
		t.Fatal("failed order with retries left should block")
	}

	svc2, source2 := renewalTestService(t)
	createRenewal(t, svc2, source2.ID, "pending", 0, time.Now())
	blocked, err = svc2.hasActiveRenewal(source2.ID, true)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !blocked {
		t.Fatal("pending order should block")
	}
}
