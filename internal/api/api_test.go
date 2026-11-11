package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"domain-manager/internal/acme"
	"domain-manager/internal/api"
	"domain-manager/internal/auth"
	"domain-manager/internal/certificate"
	"domain-manager/internal/config"
	"domain-manager/internal/database"
	"domain-manager/internal/monitor"
	"domain-manager/internal/notification"
	"domain-manager/internal/scheduler"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"
)

type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func setupTestServer(t *testing.T) (*httptest.Server, *cookiejar.Jar, string) {
	t.Helper()
	t.Setenv("DM_ADMIN_PASSWORD", "ApiTestPassword123!")
	t.Setenv("DM_ADMIN_USER", "admin")
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Server.Mode = "test"
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
	if err := database.SeedRules(db); err != nil {
		t.Fatalf("rules: %v", err)
	}
	if err := database.SeedJobs(db); err != nil {
		t.Fatalf("jobs: %v", err)
	}
	if _, err := database.SeedAdmin(db); err != nil {
		t.Fatalf("admin: %v", err)
	}
	st, err := settings.New(db)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	cipher, err := security.LoadOrCreateCipher(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	sessions := security.NewSessionManager(time.Hour)
	authSvc := auth.New(db, st, sessions, cipher)
	authSvc.RefreshPolicy()
	domainSvc := monitor.NewDomainService(db, st)
	sslSvc := monitor.NewSSLService(db, st)
	certSvc := certificate.NewService(db, st, dir)
	notifier := notification.NewService(db, st, cipher)
	acmeSvc := acme.NewService(db, st, cipher, certSvc, notifier, dir)
	sched := scheduler.New(db, st, domainSvc, sslSvc, acmeSvc, notifier)
	server, err := api.New(api.Options{
		Config: cfg, DB: db, Settings: st, Auth: authSvc, Sessions: sessions,
		Domains: domainSvc, SSL: sslSvc, Certs: certSvc, ACME: acmeSvc,
		Notifier: notifier, Scheduler: sched, Cipher: cipher, Version: "test",
	})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	ts := httptest.NewServer(server.Router())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, jar, "ApiTestPassword123!"
}

func requestJSON(t *testing.T, client *http.Client, method, url, csrf string, payload any) (*http.Response, apiResponse) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var parsed apiResponse
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

func TestAuthCSRFAndDomainAPI(t *testing.T) {
	ts, jar, password := setupTestServer(t)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, _ := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": "wrong",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong login status = %d", resp.StatusCode)
	}

	resp, login := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d body=%+v", resp.StatusCode, login)
	}
	var loginData struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Data, &loginData); err != nil || loginData.CSRFToken == "" {
		t.Fatalf("missing csrf token: %v %s", err, login.Data)
	}

	// An account still using the initial password must not be able to call
	// ordinary APIs even though it has a valid session.
	resp, _ = requestJSON(t, client, http.MethodGet, ts.URL+"/api/v1/dashboard", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("must-change-password dashboard status = %d", resp.StatusCode)
	}
	newPassword := "NewApiPassword123!"
	resp, _ = requestJSON(t, client, http.MethodPut, ts.URL+"/api/v1/auth/password", loginData.CSRFToken, map[string]string{
		"current_password": password, "new_password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d", resp.StatusCode)
	}
	resp, login = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relogin status = %d", resp.StatusCode)
	}
	if err := json.Unmarshal(login.Data, &loginData); err != nil || loginData.CSRFToken == "" {
		t.Fatalf("missing csrf token after password change: %v %s", err, login.Data)
	}

	resp, _ = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/domains", "", map[string]any{
		"name": "example.com", "auto_check": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d", resp.StatusCode)
	}

	resp, created := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/domains", loginData.CSRFToken, map[string]any{
		"name": "example.com", "auto_check": false,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create domain status = %d body=%s", resp.StatusCode, created.Message)
	}

	resp, dashboard := requestJSON(t, client, http.MethodGet, ts.URL+"/api/v1/dashboard", "", nil)
	if resp.StatusCode != http.StatusOK || dashboard.Code != 0 {
		t.Fatalf("dashboard status = %d code=%d", resp.StatusCode, dashboard.Code)
	}

	unauthClient := &http.Client{Timeout: 5 * time.Second}
	resp, _ = requestJSON(t, unauthClient, http.MethodGet, ts.URL+"/api/v1/domains", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", resp.StatusCode)
	}
}

func TestTOTPEnrollmentAndLogin(t *testing.T) {
	ts, jar, password := setupTestServer(t)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	newPassword := "TotpPassword123!"
	_, login := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": password,
	})
	var data struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Data, &data)
	resp, _ := requestJSON(t, client, http.MethodPut, ts.URL+"/api/v1/auth/password", data.CSRFToken, map[string]string{
		"current_password": password, "new_password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d", resp.StatusCode)
	}
	_, login = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": newPassword,
	})
	_ = json.Unmarshal(login.Data, &data)

	resp, setup := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/totp/setup", data.CSRFToken, map[string]string{
		"password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp setup status = %d body=%s", resp.StatusCode, setup.Message)
	}
	var setupData struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(setup.Data, &setupData); err != nil || setupData.Secret == "" || setupData.OTPAuthURL == "" {
		t.Fatalf("invalid setup data: %v %s", err, setup.Data)
	}
	code, err := security.GenerateTOTPCode(setupData.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	resp, enabled := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/totp/enable", data.CSRFToken, map[string]string{
		"code": code,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp enable status = %d body=%s", resp.StatusCode, enabled.Message)
	}
	var enableData struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(enabled.Data, &enableData); err != nil || len(enableData.RecoveryCodes) == 0 {
		t.Fatalf("missing recovery codes: %v %s", err, enabled.Data)
	}

	resp, _ = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/logout", data.CSRFToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	resp, login = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp password step status = %d", resp.StatusCode)
	}
	var challenge struct {
		TOTPRequired   bool   `json:"totp_required"`
		ChallengeToken string `json:"challenge_token"`
		CSRFToken      string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Data, &challenge); err != nil || !challenge.TOTPRequired || challenge.ChallengeToken == "" {
		t.Fatalf("expected TOTP challenge: %v %s", err, login.Data)
	}
	if challenge.CSRFToken != "" {
		t.Fatal("password step must not issue a session before TOTP")
	}

	code, _ = security.GenerateTOTPCode(setupData.Secret, time.Now().Add(30*time.Second))
	resp, login = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login/totp", "", map[string]string{
		"challenge_token": challenge.ChallengeToken, "code": code,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp login status = %d body=%s", resp.StatusCode, login.Message)
	}
	_ = json.Unmarshal(login.Data, &data)
	if data.CSRFToken == "" {
		t.Fatal("totp login did not return a csrf token")
	}
	resp, me := requestJSON(t, client, http.MethodGet, ts.URL+"/api/v1/auth/me", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d", resp.StatusCode)
	}
	var meData struct {
		User struct {
			TOTPEnabled bool `json:"totp_enabled"`
		} `json:"user"`
	}
	if err := json.Unmarshal(me.Data, &meData); err != nil || !meData.User.TOTPEnabled {
		t.Fatalf("totp_enabled not reported: %v %s", err, me.Data)
	}
}

func TestCSRFAllowsConfiguredPublicURL(t *testing.T) {
	ts, jar, password := setupTestServer(t)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	_, login := requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": password,
	})
	var data struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Data, &data)
	newPassword := "CsrfNewPassword123!"
	resp, _ := requestJSON(t, client, http.MethodPut, ts.URL+"/api/v1/auth/password", data.CSRFToken, map[string]string{
		"current_password": password, "new_password": newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d", resp.StatusCode)
	}
	_, login = requestJSON(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": newPassword,
	})
	_ = json.Unmarshal(login.Data, &data)
	resp, _ = requestJSON(t, client, http.MethodPut, ts.URL+"/api/v1/settings", data.CSRFToken, map[string]any{
		"settings": map[string]string{"public_url": "https://dm.example.com"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save public_url status = %d", resp.StatusCode)
	}

	makeRequest := func(origin string) int {
		body, _ := json.Marshal(map[string]any{"name": "origin.example.com", "auto_check": false})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/domains", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", data.CSRFToken)
		req.Header.Set("Origin", origin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if status := makeRequest("https://dm.example.com"); status != http.StatusCreated {
		t.Fatalf("configured public_url origin status = %d", status)
	}
	if status := makeRequest("https://evil.example.com"); status != http.StatusForbidden {
		t.Fatalf("untrusted origin status = %d", status)
	}
}

func TestSPAFallbackAndHealth(t *testing.T) {
	ts, _, _ := setupTestServer(t)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(ts.URL + "/domains")
	if err != nil {
		t.Fatalf("get spa: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("spa status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("SPA content type = %q, want text/html", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("<div id=\"app\">")) {
		t.Fatal("SPA index was not served")
	}
	resp, err = client.Get(ts.URL + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %v %v", resp.StatusCode, err)
	}
}
