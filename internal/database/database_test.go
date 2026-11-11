package database

import (
	"os"
	"path/filepath"
	"testing"

	"domain-manager/internal/models"

	"gorm.io/gorm"
)

func openTestDB(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := SeedRules(db); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if err := SeedJobs(db); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	return db, dir
}

func TestMigrateAndSeedIdempotent(t *testing.T) {
	db, _ := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := SeedRules(db); err != nil {
		t.Fatalf("second seed rules: %v", err)
	}
	var rules, jobs int64
	db.Model(&models.NotificationRule{}).Count(&rules)
	db.Model(&models.ScheduledJob{}).Count(&jobs)
	if rules != 7 {
		t.Fatalf("rules = %d, want 7", rules)
	}
	if jobs != 7 {
		t.Fatalf("jobs = %d, want 7", jobs)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	db, dir := openTestDB(t)
	domain := models.Domain{Name: "example.com", Status: models.DomainStatusNormal, MonitorEnabled: true, Notes: "before"}
	if err := db.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}
	backupPath := filepath.Join(dir, "backup.db")
	if err := Backup(db, backupPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := db.Model(&domain).Update("notes", "after").Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := Restore(db, backupPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	var got models.Domain
	if err := db.First(&got, domain.ID).Error; err != nil {
		t.Fatalf("read restored domain: %v", err)
	}
	if got.Notes != "before" {
		t.Fatalf("restored notes = %q, want before", got.Notes)
	}
}

func TestIntersectColumnsIgnoresNewAndRemovedColumns(t *testing.T) {
	live := []string{"id", "name", "added_in_new_version"}
	backup := []string{"id", "name", "removed_old_column"}
	got := intersectColumns(live, backup)
	if len(got) != 2 || got[0] != "id" || got[1] != "name" {
		t.Fatalf("intersection = %v", got)
	}
}

func TestFullBackupEncryptsAndRestoresSecrets(t *testing.T) {
	db, dir := openTestDB(t)
	domain := models.Domain{Name: "full.example.com", Status: models.DomainStatusNormal, MonitorEnabled: true, Notes: "before"}
	if err := db.Create(&domain).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	certDir := filepath.Join(dir, "certs", "1")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatalf("cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), []byte("private-key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "backup.dmbak")
	if err := FullBackup(db, dir, dest, "backup-password"); err != nil {
		t.Fatalf("full backup: %v", err)
	}
	full, err := IsFullBackup(dest)
	if err != nil || !full {
		t.Fatalf("full backup header: %v %v", full, err)
	}
	if err := db.Model(&domain).Update("notes", "after").Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), []byte("changed"), 0o600); err != nil {
		t.Fatalf("change key: %v", err)
	}
	if err := RestoreFull(db, dest, dir, "wrong-password"); err == nil {
		t.Fatal("wrong password should fail")
	}
	if err := RestoreFull(db, dest, dir, "backup-password"); err != nil {
		t.Fatalf("restore full: %v", err)
	}
	var got models.Domain
	if err := db.First(&got, domain.ID).Error; err != nil {
		t.Fatalf("read domain: %v", err)
	}
	if got.Notes != "before" {
		t.Fatalf("restored notes = %q", got.Notes)
	}
	key, err := os.ReadFile(filepath.Join(certDir, "privkey.pem"))
	if err != nil || string(key) != "private-key" {
		t.Fatalf("restored key = %q err=%v", key, err)
	}
}

func TestSeedAdmin(t *testing.T) {
	db, _ := openTestDB(t)
	t.Setenv("DM_ADMIN_PASSWORD", "UnitTestPassword123!")
	t.Setenv("DM_ADMIN_USER", "root")
	admin, err := SeedAdmin(db)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if !admin.Created || admin.Username != "root" {
		t.Fatalf("unexpected admin result: %+v", admin)
	}
	second, err := SeedAdmin(db)
	if err != nil {
		t.Fatalf("second seed admin: %v", err)
	}
	if second.Created {
		t.Fatal("admin should only be created once")
	}
}
