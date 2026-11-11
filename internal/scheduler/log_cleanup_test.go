package scheduler

import (
	"path/filepath"
	"testing"
	"time"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/settings"
)

func TestLogCleanupRemovesOnlyOldRows(t *testing.T) {
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
	old := time.Now().AddDate(0, 0, -100)
	recent := time.Now().AddDate(0, 0, -1)
	rows := []any{
		&models.MonitorLog{Kind: "ssl", Target: "old", CreatedAt: old},
		&models.MonitorLog{Kind: "ssl", Target: "new", CreatedAt: recent},
		&models.NotificationLog{Event: "test", Status: "success", CreatedAt: old},
		&models.JobRun{JobKey: "ssl_check", Status: "success", StartedAt: old},
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create row: %v", err)
		}
	}
	s := &Scheduler{db: db, settings: st}
	if _, err := s.jobLogCleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	var monitor, notifications, runs int64
	db.Model(&models.MonitorLog{}).Count(&monitor)
	db.Model(&models.NotificationLog{}).Count(&notifications)
	db.Model(&models.JobRun{}).Count(&runs)
	if monitor != 1 || notifications != 0 || runs != 0 {
		t.Fatalf("remaining monitor=%d notifications=%d runs=%d", monitor, notifications, runs)
	}
}
