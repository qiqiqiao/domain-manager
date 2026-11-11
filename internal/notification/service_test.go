package notification

import (
	"context"
	"path/filepath"
	"testing"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"
)

type captureSender struct {
	cfg     ChannelConfig
	channel string
}

func (s *captureSender) Send(_ context.Context, channelType string, cfg ChannelConfig, _ Message) error {
	s.channel = channelType
	s.cfg = cfg
	return nil
}

func TestTestChannelPassesDecryptedConfigToSender(t *testing.T) {
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
	cipher, err := security.LoadOrCreateCipher(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := NewService(db, st, cipher)
	fake := &captureSender{}
	svc.sender = fake

	encrypted, err := svc.EncryptConfig(ChannelConfig{BotToken: "12345:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatID: "-100123"})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	channel := &models.NotificationChannel{
		ID: 1, Name: "telegram", Type: models.ChannelTelegram, ConfigEncrypted: encrypted, Enabled: true,
	}
	if err := svc.TestChannel(t.Context(), channel); err != nil {
		t.Fatalf("test channel: %v", err)
	}
	if fake.channel != models.ChannelTelegram {
		t.Fatalf("channel type = %q", fake.channel)
	}
	if fake.cfg.BotToken != "12345:ABCDEFGHIJKLMNOPQRSTUVWXYZ" || fake.cfg.ChatID != "-100123" {
		t.Fatalf("sender received wrong config: %+v", fake.cfg)
	}
}
