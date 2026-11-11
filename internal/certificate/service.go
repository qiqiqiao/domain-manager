package certificate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"
	"domain-manager/internal/security"
	"domain-manager/internal/settings"

	"gorm.io/gorm"
)

type StoredFiles struct {
	CertPath      string
	ChainPath     string
	FullchainPath string
	KeyPath       string
}

type Service struct {
	db       *gorm.DB
	settings *settings.Manager
	dataDir  string
}

func NewService(db *gorm.DB, st *settings.Manager, dataDir string) *Service {
	return &Service{db: db, settings: st, dataDir: dataDir}
}

// StoreFiles writes PEM files with strict permissions. The private key is
// never exposed through list/detail APIs and never logged.
func (s *Service) StoreFiles(certID uint, privateKey, fullchain, issuer []byte) (*StoredFiles, error) {
	if len(privateKey) == 0 || len(fullchain) == 0 {
		return nil, errors.New("证书或私钥内容为空")
	}
	dir := filepath.Join(s.dataDir, "certs", fmt.Sprintf("%d", certID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	blocks := pemBlocks(fullchain)
	if len(blocks) == 0 {
		return nil, errors.New("签发的证书不是有效的 PEM 数据")
	}
	leafPEM := pem.EncodeToMemory(blocks[0])
	var chainPEM []byte
	for _, block := range blocks[1:] {
		chainPEM = append(chainPEM, pem.EncodeToMemory(block)...)
	}
	if len(issuer) > 0 {
		issuerBlocks := pemBlocks(issuer)
		for _, block := range issuerBlocks {
			if !containsBlock(blocks, block) {
				chainPEM = append(chainPEM, pem.EncodeToMemory(block)...)
			}
		}
	}
	files := &StoredFiles{
		CertPath:      filepath.Join(dir, "cert.pem"),
		ChainPath:     filepath.Join(dir, "chain.pem"),
		FullchainPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:       filepath.Join(dir, "privkey.pem"),
	}
	err := writeDirAtomic(dir, []fileSpec{
		{name: "cert.pem", data: leafPEM, mode: 0o644},
		{name: "chain.pem", data: chainPEM, mode: 0o644},
		{name: "fullchain.pem", data: fullchain, mode: 0o644},
		{name: "privkey.pem", data: privateKey, mode: 0o600},
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

type fileSpec struct {
	name string
	data []byte
	mode os.FileMode
}

// writeDirAtomic stages a complete set of files in a sibling directory and
// swaps it into place with rename. Readers therefore never observe a new
// certificate next to an old private key.
func writeDirAtomic(dir string, files []fileSpec) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tmp := filepath.Join(parent, "."+filepath.Base(dir)+".tmp-"+suffix)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, file := range files {
		path := filepath.Join(tmp, file.name)
		if err := writeFile(path, file.data, file.mode); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return err
	}

	backup := dir + ".old-" + suffix
	exists := false
	if _, statErr := os.Stat(dir); statErr == nil {
		exists = true
		if err := os.Rename(dir, backup); err != nil {
			return fmt.Errorf("切换目录前备份失败: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := os.Rename(tmp, dir); err != nil {
		if exists {
			_ = os.Rename(backup, dir)
		}
		return fmt.Errorf("切换证书目录失败: %w", err)
	}
	cleanup = false
	if exists {
		_ = os.RemoveAll(backup)
	}
	syncDir(parent)
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func syncDir(path string) {
	if d, err := os.Open(path); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func randomSuffix() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func pemBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
		rest = r
	}
	return blocks
}

func containsBlock(blocks []*pem.Block, target *pem.Block) bool {
	for _, b := range blocks {
		if string(b.Bytes) == string(target.Bytes) {
			return true
		}
	}
	return false
}

// ParseLeaf extracts the first certificate from a PEM bundle.
func ParseLeaf(fullchain []byte) (*x509.Certificate, error) {
	blocks := pemBlocks(fullchain)
	if len(blocks) == 0 {
		return nil, errors.New("证书 PEM 内容为空")
	}
	return x509.ParseCertificate(blocks[0].Bytes)
}

type DownloadFile struct {
	Name        string
	Data        []byte
	ContentType string
}

func (s *Service) ReadFile(cert *models.SSLCertificate, kind string) (*DownloadFile, error) {
	var path, name string
	switch kind {
	case "cert":
		path, name = cert.CertPath, "cert.pem"
	case "chain":
		path, name = cert.CertPath, "chain.pem"
		if cert.CertPath != "" {
			path = filepath.Join(filepath.Dir(cert.CertPath), "chain.pem")
		}
	case "fullchain":
		path, name = cert.FullchainPath, "fullchain.pem"
	case "privkey":
		path, name = cert.KeyPath, "privkey.pem"
	default:
		return nil, errors.New("不支持的下载文件类型")
	}
	if path == "" {
		return nil, errors.New("证书文件不存在")
	}
	clean := filepath.Clean(path)
	base := filepath.Clean(filepath.Join(s.dataDir, "certs"))
	if !strings.HasPrefix(clean, base+string(os.PathSeparator)) {
		return nil, errors.New("证书文件路径非法")
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}
	return &DownloadFile{Name: name, Data: data, ContentType: "application/x-pem-file"}, nil
}

func (s *Service) Deploy(ctx context.Context, cert *models.SSLCertificate) (string, error) {
	if cert.FullchainPath == "" || cert.KeyPath == "" {
		return "", errors.New("该证书没有本地签发文件，无法部署")
	}
	if _, err := os.Stat(cert.FullchainPath); err != nil {
		return "", errors.New("证书文件不存在")
	}
	deployDir := strings.TrimSpace(s.settings.Get("deploy_dir"))
	if deployDir == "" {
		deployDir = filepath.Join(s.dataDir, "deploy")
	}
	deployDir = filepath.Clean(deployDir)
	domainDir := filepath.Join(deployDir, safeName(cert.Domain))
	if err := os.MkdirAll(domainDir, 0o700); err != nil {
		return "", fmt.Errorf("创建部署目录失败: %w", err)
	}
	sources := map[string]string{
		"fullchain.pem": cert.FullchainPath,
		"privkey.pem":   cert.KeyPath,
	}
	if cert.CertPath != "" {
		sources["cert.pem"] = cert.CertPath
		chain := filepath.Join(filepath.Dir(cert.CertPath), "chain.pem")
		if _, err := os.Stat(chain); err == nil {
			sources["chain.pem"] = chain
		}
	}
	order := []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}
	files := make([]fileSpec, 0, len(sources))
	for _, name := range order {
		src, ok := sources[name]
		if !ok {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("读取 %s 失败: %w", name, err)
		}
		mode := os.FileMode(0o644)
		if name == "privkey.pem" {
			mode = 0o600
		}
		files = append(files, fileSpec{name: name, data: data, mode: mode})
	}
	if err := writeDirAtomic(domainDir, files); err != nil {
		return "", fmt.Errorf("写入部署文件失败: %w", err)
	}
	script := strings.TrimSpace(s.settings.Get("deploy_script"))
	if script != "" {
		if !filepath.IsAbs(script) {
			return domainDir, errors.New("部署脚本必须使用绝对路径")
		}
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(runCtx, script)
		cmd.Env = deployEnv(cert.Domain, domainDir)
		output := &cappedBuffer{max: 64 * 1024}
		cmd.Stdout = output
		cmd.Stderr = output
		err := cmd.Run()
		if output.buf.Len() > 0 {
			logger.L().Info("证书部署脚本输出", "domain", cert.Domain, "output", limit(output.buf.String(), 2000))
		}
		if err != nil {
			return domainDir, fmt.Errorf("部署脚本执行失败: %w", err)
		}
	}
	if err := os.Chmod(domainDir, 0o700); err != nil {
		return "", err
	}
	logger.L().Info("证书已部署", "domain", cert.Domain, "dir", domainDir)
	return domainDir, nil
}

func (s *Service) DeleteFiles(cert *models.SSLCertificate) error {
	base := filepath.Clean(filepath.Join(s.dataDir, "certs"))
	if cert.CertPath == "" && cert.KeyPath == "" && cert.FullchainPath == "" {
		return nil
	}
	dirs := map[string]bool{}
	for _, p := range []string{cert.CertPath, cert.KeyPath, cert.FullchainPath} {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if strings.HasPrefix(clean, base+string(os.PathSeparator)) {
			dirs[filepath.Dir(clean)] = true
		}
	}
	for dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return nil
}

func safeName(domain string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_", "*", "wildcard", ":", "_")
	name := replacer.Replace(domain)
	if name == "" {
		return "certificate"
	}
	return name
}

func limit(s string, n int) string {
	return security.TruncateRunes(s, n)
}

// deployEnv deliberately does not inherit the service environment. That keeps
// DM_ADMIN_PASSWORD and other deployment secrets out of deploy scripts.
func deployEnv(domain, dir string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return []string{
		"PATH=" + path,
		"CERT_DOMAIN=" + domain,
		"CERT_DIR=" + dir,
		"CERT_FULLCHAIN=" + filepath.Join(dir, "fullchain.pem"),
		"CERT_PRIVKEY=" + filepath.Join(dir, "privkey.pem"),
		"CERT_CERT=" + filepath.Join(dir, "cert.pem"),
		"CERT_CHAIN=" + filepath.Join(dir, "chain.pem"),
	}
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	if w.max <= 0 || w.buf.Len() < w.max {
		remaining := w.max - w.buf.Len()
		if w.max <= 0 || len(p) <= remaining {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:remaining])
		}
	}
	return len(p), nil
}
