package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk and runtime configuration of Domain Manager.
type Config struct {
	Server     ServerConfig `yaml:"server"`
	DataDir    string       `yaml:"data_dir"`
	LogDir     string       `yaml:"log_dir"`
	DBPath     string       `yaml:"database_path"`
	ConfigFile string       `yaml:"-"`
	LogLevel   string       `yaml:"log_level"`
}

type ServerConfig struct {
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	Mode           string   `yaml:"mode"` // release, debug, test
	CookieSecure   bool     `yaml:"cookie_secure"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	ReadTimeout    int      `yaml:"read_timeout_seconds"`
	WriteTimeout   int      `yaml:"write_timeout_seconds"`
	MaxUploadMB    int      `yaml:"max_upload_mb"`
}

func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "127.0.0.1",
			Port:         10120,
			Mode:         "release",
			CookieSecure: false,
			ReadTimeout:  30,
			WriteTimeout: 60,
			MaxUploadMB:  100,
		},
		DataDir:  "./data",
		LogDir:   "./logs",
		DBPath:   "./data/domain-manager.db",
		LogLevel: "info",
	}
}

// Load reads configs/config.yaml if it exists, creates a default file when
// missing, then applies environment variable overrides.
func Load(path string) (*Config, error) {
	if path == "" {
		path = "configs/config.yaml"
	}

	cfg := Defaults()
	cfg.ConfigFile = path

	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	} else {
		if err := writeDefault(path, cfg); err != nil {
			return nil, err
		}
	}

	applyEnv(cfg)
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	c.Server.Host = strings.TrimSpace(c.Server.Host)
	if c.Server.Host == "" {
		c.Server.Host = "127.0.0.1"
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("监听端口无效: %d", c.Server.Port)
	}
	switch c.Server.Mode {
	case "release", "debug", "test":
	default:
		return fmt.Errorf("server.mode 必须为 release/debug/test")
	}
	if c.Server.ReadTimeout <= 0 {
		c.Server.ReadTimeout = 30
	}
	if c.Server.WriteTimeout <= 0 {
		c.Server.WriteTimeout = 60
	}
	if c.Server.MaxUploadMB <= 0 {
		c.Server.MaxUploadMB = 100
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.LogDir == "" {
		c.LogDir = "./logs"
	}
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "domain-manager.db")
	}
	return nil
}

func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// IsLoopbackListen reports whether the configured listener is only reachable
// from the local machine. An empty host means all interfaces on most systems.
func (c *Config) IsLoopbackListen() bool {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(c.Server.Host)), "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) EnsureDirs() error {
	for _, dir := range []string{c.DataDir, c.LogDir, filepath.Dir(c.DBPath), filepath.Join(c.DataDir, "certs"), filepath.Join(c.DataDir, "acme"), filepath.Join(c.DataDir, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("设置目录权限失败: %w", err)
		}
	}
	return nil
}

func writeDefault(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入默认配置文件失败: %w", err)
	}
	return nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("DM_ADDR"); v != "" {
		host, port, ok := splitAddr(v)
		if ok {
			c.Server.Host = host
			c.Server.Port = port
		} else {
			c.Server.Host = v
		}
	}
	if v := os.Getenv("DM_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.Server.Port = p
		}
	}
	if v := os.Getenv("DM_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("DM_LOG_DIR"); v != "" {
		c.LogDir = v
	}
	if v := os.Getenv("DM_DB_PATH"); v != "" {
		c.DBPath = v
	}
	if v := os.Getenv("DM_GIN_MODE"); v != "" {
		c.Server.Mode = v
	}
	if v := os.Getenv("DM_COOKIE_SECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Server.CookieSecure = b
		}
	}
	if v := os.Getenv("DM_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
}

func splitAddr(v string) (string, int, bool) {
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(v[i+1:])
	if err != nil {
		return "", 0, false
	}
	return strings.Trim(v[:i], "[]"), p, true
}
