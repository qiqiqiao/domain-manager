package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	certstore "domain-manager/internal/certificate"
	"domain-manager/internal/config"
	"domain-manager/internal/database"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"github.com/go-acme/lego/v4/certcrypto"
	legocert "github.com/go-acme/lego/v4/certificate"
)

func testCertificate(t *testing.T, domains []string) (*x509.Certificate, []byte, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: domains[0], Organization: []string{"Domain Manager Test"}},
		Issuer:       pkix.Name{CommonName: "Test ACME CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     domains,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := certcrypto.PEMEncode(key)
	return leaf, certPEM, keyPEM, certPEM
}

func TestSaveCertificateFilesAndDeploy(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.LogDir = filepath.Join(dir, "logs")
	cfg.DBPath = filepath.Join(dir, "test.db")
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatalf("dirs: %v", err)
	}
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("db: %v", err)
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
	_ = cipher
	certSvc := certstore.NewService(db, st, dir)
	svc := NewService(db, st, cipher, certSvc, nil, dir)

	leaf, certPEM, keyPEM, issuerPEM := testCertificate(t, []string{"test.example.com", "www.test.example.com"})
	order := models.CertificateOrder{
		PrimaryDomain: "test.example.com", DomainsJSON: `["test.example.com","www.test.example.com"]`,
		ChallengeType: "http-01", KeyType: "rsa2048", Email: "test@example.com",
		Status: "running", MaxAttempts: 3, AutoRenew: true,
	}
	if err := db.Create(&order).Error; err != nil {
		t.Fatalf("create order: %v", err)
	}
	res := &legocert.Resource{Certificate: certPEM, PrivateKey: keyPEM, IssuerCertificate: issuerPEM}
	cert, files, err := svc.saveCertificate(&order, leaf, res)
	if err != nil {
		t.Fatalf("save certificate: %v", err)
	}
	if !cert.Managed || !cert.AutoRenew || cert.OrderID == nil || *cert.OrderID != order.ID {
		t.Fatalf("unexpected certificate record: %+v", cert)
	}
	if cert.NotAfter == nil || cert.SAN == "" {
		t.Fatal("certificate metadata missing")
	}
	if files.KeyPath == "" || files.FullchainPath == "" {
		t.Fatal("certificate paths missing")
	}
	info, err := os.Stat(files.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", info.Mode().Perm())
	}
	keyData, err := os.ReadFile(files.KeyPath)
	if err != nil || len(keyData) == 0 {
		t.Fatalf("read key: %v", err)
	}

	download, err := certSvc.ReadFile(cert, "fullchain")
	if err != nil || len(download.Data) == 0 {
		t.Fatalf("read fullchain: %v", err)
	}
	keyFile, err := certSvc.ReadFile(cert, "privkey")
	if err != nil || len(keyFile.Data) == 0 {
		t.Fatalf("read private key: %v", err)
	}

	deployDir := filepath.Join(dir, "deploy")
	if err := st.Update(map[string]string{"deploy_dir": deployDir}); err != nil {
		t.Fatalf("update deploy dir: %v", err)
	}
	if err := st.Reload(); err != nil {
		t.Fatalf("reload settings: %v", err)
	}
	target, err := certSvc.Deploy(t.Context(), cert)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	deployedKey := filepath.Join(target, "privkey.pem")
	info, err = os.Stat(deployedKey)
	if err != nil {
		t.Fatalf("stat deployed key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("deployed key permissions = %o", info.Mode().Perm())
	}
	if _, err := certSvc.ReadFile(cert, "unknown"); err == nil {
		t.Fatal("unknown download type should fail")
	}
}

func TestCertificateMonitorDomainWildcard(t *testing.T) {
	order := &models.CertificateOrder{PrimaryDomain: "*.example.com", DomainsJSON: `["*.example.com"]`}
	domain, canMonitor := certificateMonitorDomain(order)
	if domain != "*.example.com" || canMonitor {
		t.Fatalf("wildcard-only domain = %q monitor=%v", domain, canMonitor)
	}
	order = &models.CertificateOrder{PrimaryDomain: "*.example.com", DomainsJSON: `["*.example.com","www.example.com"]`}
	domain, canMonitor = certificateMonitorDomain(order)
	if domain != "www.example.com" || !canMonitor {
		t.Fatalf("SAN domain = %q monitor=%v", domain, canMonitor)
	}
}
