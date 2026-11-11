package certificate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/settings"
)

func TestDeployScriptDoesNotInheritProcessSecrets(t *testing.T) {
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
	certDir := filepath.Join(dir, "certs", "1")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatalf("cert dir: %v", err)
	}
	files := map[string]string{
		"cert.pem":      "cert",
		"chain.pem":     "chain",
		"fullchain.pem": "fullchain",
		"privkey.pem":   "key",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(certDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	deployDir := filepath.Join(dir, "deploy")
	script := filepath.Join(dir, "deploy.sh")
	scriptBody := "#!/bin/sh\nenv > \"$CERT_DIR/env.txt\"\n"
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := st.Update(map[string]string{"deploy_dir": deployDir, "deploy_script": script}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if err := st.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Setenv("DM_ADMIN_PASSWORD", "super-secret")
	svc := NewService(db, st, dir)
	cert := &models.SSLCertificate{
		Domain: "example.com", CertPath: filepath.Join(certDir, "cert.pem"),
		FullchainPath: filepath.Join(certDir, "fullchain.pem"),
		KeyPath:       filepath.Join(certDir, "privkey.pem"),
	}
	target, err := svc.Deploy(t.Context(), cert)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	envData, err := os.ReadFile(filepath.Join(target, "env.txt"))
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	env := string(envData)
	if strings.Contains(env, "super-secret") || strings.Contains(env, "DM_ADMIN_PASSWORD") {
		t.Fatalf("deploy script inherited process secrets:\n%s", env)
	}
	if !strings.Contains(env, "CERT_DOMAIN=example.com") || !strings.Contains(env, "PATH=") {
		t.Fatalf("missing expected deploy environment:\n%s", env)
	}
}
