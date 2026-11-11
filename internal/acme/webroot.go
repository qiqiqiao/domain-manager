package acme

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// webrootProvider writes HTTP-01 tokens into an existing web root. An external
// web server must serve /.well-known/acme-challenge/ from this directory.
type webrootProvider struct {
	root string
}

func newWebrootProvider(root string) (*webrootProvider, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("Webroot 路径不能为空")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(abs, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建 Webroot 验证目录失败: %w", err)
	}
	return &webrootProvider{root: abs}, nil
}

func (p *webrootProvider) Present(domain, token, keyAuth string) error {
	if !tokenRE.MatchString(token) {
		return errors.New("ACME token 格式非法")
	}
	path := filepath.Join(p.root, ".well-known", "acme-challenge", token)
	if err := os.WriteFile(path, []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("写入 HTTP-01 验证文件失败: %w", err)
	}
	return nil
}

func (p *webrootProvider) CleanUp(domain, token, keyAuth string) error {
	if !tokenRE.MatchString(token) {
		return nil
	}
	path := filepath.Join(p.root, ".well-known", "acme-challenge", token)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (p *webrootProvider) Timeout() (time.Duration, time.Duration) {
	return 60 * time.Second, 2 * time.Second
}
