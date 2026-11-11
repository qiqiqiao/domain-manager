package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"domain-manager/internal/acme"
	"domain-manager/internal/api"
	"domain-manager/internal/auth"
	"domain-manager/internal/certificate"
	"domain-manager/internal/config"
	"domain-manager/internal/database"
	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/monitor"
	"domain-manager/internal/notification"
	"domain-manager/internal/scheduler"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"
)

var (
	version   = "dev"
	buildTime = "unknown"
	commit    = "dev"
)

func main() {
	configPath := flag.String("config", "", "配置文件路径（默认 configs/config.yaml）")
	port := flag.Int("port", 0, "HTTP 监听端口（覆盖配置文件）")
	dataDir := flag.String("data-dir", "", "数据目录（覆盖配置文件）")
	showVersion := flag.Bool("version", false, "显示版本号")
	flag.Parse()

	if *showVersion {
		fmt.Printf("domain-manager %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}
	if err := run(*configPath, *port, *dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string, port int, dataDirOverride string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if port > 0 {
		cfg.Server.Port = port
	}
	if dataDirOverride != "" {
		cfg.DataDir = dataDirOverride
		if cfg.DBPath == "./data/domain-manager.db" || cfg.DBPath == "" {
			cfg.DBPath = dataDirOverride + "/domain-manager.db"
		}
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	if _, err := logger.Setup(cfg.LogDir, cfg.LogLevel); err != nil {
		return err
	}
	log := logger.L()
	log.Info("Domain Manager 正在启动", "version", version, "commit", commit, "build_time", buildTime)

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := database.Migrate(db); err != nil {
		return err
	}
	if err := database.SeedRules(db); err != nil {
		return err
	}
	if err := database.SeedJobs(db); err != nil {
		return err
	}
	initialAdmin, err := database.SeedAdmin(db)
	if err != nil {
		return err
	}

	settingsMgr, err := settings.New(db)
	if err != nil {
		return err
	}
	if !cfg.IsLoopbackListen() {
		publicURL := strings.ToLower(strings.TrimSpace(settingsMgr.Get("public_url")))
		secure := cfg.Server.CookieSecure || strings.HasPrefix(publicURL, "https://")
		if !secure {
			log.Warn("服务监听在非本地地址，但未检测到 HTTPS 配置；请通过反向代理提供 HTTPS，并设置 public_url 与 cookie_secure",
				"listen", cfg.ListenAddr())
		}
	}
	cipher, err := security.LoadOrCreateCipher(cfg.DataDir + "/secret.key")
	if err != nil {
		return err
	}
	sessions := security.NewSessionManager(time.Duration(settingsMgr.Int("session_ttl_hours")) * time.Hour)
	authSvc := auth.New(db, settingsMgr, sessions, cipher)
	authSvc.RefreshPolicy()

	domainSvc := monitor.NewDomainService(db, settingsMgr)
	sslSvc := monitor.NewSSLService(db, settingsMgr)
	certSvc := certificate.NewService(db, settingsMgr, cfg.DataDir)
	notifier := notification.NewService(db, settingsMgr, cipher)
	acmeSvc := acme.NewService(db, settingsMgr, cipher, certSvc, notifier, cfg.DataDir)
	if err := acmeSvc.RecoverStuck(); err != nil {
		log.Warn("恢复中断的 ACME 订单失败", "error", err)
	}
	sched := scheduler.New(db, settingsMgr, domainSvc, sslSvc, acmeSvc, notifier)

	apiServer, err := api.New(api.Options{
		Config: cfg, DB: db, Settings: settingsMgr, Auth: authSvc, Sessions: sessions,
		Domains: domainSvc, SSL: sslSvc, Certs: certSvc, ACME: acmeSvc, Notifier: notifier,
		Scheduler: sched, Cipher: cipher, Version: version,
	})
	if err != nil {
		return err
	}
	router := apiServer.Router()
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	passwordFile := filepath.Join(cfg.DataDir, "initial-admin-password")
	if initialAdmin != nil && initialAdmin.Created {
		if !initialAdmin.FromEnv {
			if err := writeSecretFile(passwordFile, initialAdmin.Password); err != nil {
				log.Warn("写入初始管理员密码文件失败", "error", err)
			}
		}
		fmt.Println("============================================================")
		fmt.Println(" Domain Manager 首次初始化完成")
		fmt.Printf(" 管理后台: http://%s\n", cfg.ListenAddr())
		fmt.Printf(" 管理员账号: %s\n", initialAdmin.Username)
		if initialAdmin.FromEnv {
			fmt.Println(" 管理员密码: 已通过 DM_ADMIN_PASSWORD 环境变量设置")
		} else {
			fmt.Printf(" 初始密码文件: %s（权限 0600，请登录后立即删除）\n", passwordFile)
		}
		fmt.Println(" 请立即登录并修改密码！首次登录未修改密码前，其他 API 将返回 403。")
		fmt.Println(" 所有域名与证书数据保存在: " + cfg.DBPath)
		fmt.Println("============================================================")
	} else if initialAdmin != nil {
		// Do not leave a stale initial password file after the account exists.
		_ = os.Remove(passwordFile)
	}

	if err := sched.Start(); err != nil {
		return fmt.Errorf("启动定时任务失败: %w", err)
	}
	defer sched.Stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("HTTP 服务已启动", "addr", cfg.ListenAddr(), "mode", cfg.Server.Mode)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-stop:
		log.Info("收到退出信号，正在关闭服务", "signal", sig.String())
	case err := <-errCh:
		return fmt.Errorf("HTTP 服务异常: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Warn("HTTP 服务关闭超时", "error", err)
	}
	sched.Stop()
	_ = db.Model(&models.CertificateOrder{}).Where("status = ?", "running").
		Updates(map[string]any{"status": "failed", "last_error": "程序关闭导致任务中断", "next_retry_at": time.Now().Add(2 * time.Minute)}).Error
	log.Info("Domain Manager 已安全退出")
	return nil
}

func writeSecretFile(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
