package database

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
	"gorm.io/gorm"
)

const (
	fullBackupMagic   = "DMBACKUP1\n"
	fullBackupVersion = 1
	fullBackupMaxSize = int64(4 << 30)
	scryptN           = 1 << 15
	scryptR           = 8
	scryptP           = 1
	scryptKeyLen      = 32
	saltLen           = 16
)

var (
	fullBackupSaltLen  = saltLen
	fullBackupNonceLen = 12
)

// IsFullBackup reports whether path starts with the encrypted full-backup
// magic header instead of looking like a plain SQLite database.
func IsFullBackup(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	header := make([]byte, len(fullBackupMagic))
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, err
	}
	return n == len(header) && string(header) == fullBackupMagic, nil
}

// FullBackup creates a consistent database snapshot plus the secrets and
// certificate files under dataDir, then encrypts the archive with a
// password-derived key.
func FullBackup(db *gorm.DB, dataDir, dest, password string) error {
	if len([]rune(password)) < 8 {
		return errors.New("完整备份口令至少需要 8 个字符")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "dm-fullbackup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	snapshot := filepath.Join(work, "domain-manager.db")
	if err := Backup(db, snapshot); err != nil {
		return err
	}
	archive := filepath.Join(work, "data.tar.gz")
	if err := writeDataArchive(dataDir, snapshot, archive); err != nil {
		return err
	}
	plain, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	defer clearBytes(plain)

	sealed, err := sealFullBackup(plain, password)
	if err != nil {
		return err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// RestoreFull decrypts a full backup, restores the database through the live
// connection, and copies the secret/certificate files into dataDir.
func RestoreFull(db *gorm.DB, source, dataDir, password string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if info.Size() > fullBackupMaxSize {
		return errors.New("完整备份文件超过 4GB")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	defer clearBytes(data)
	plain, err := openFullBackup(data, password)
	if err != nil {
		return err
	}
	defer clearBytes(plain)

	staging, err := os.MkdirTemp("", "dm-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := extractDataArchive(plain, staging); err != nil {
		return err
	}
	dbPath := filepath.Join(staging, "domain-manager.db")
	if _, err := os.Stat(dbPath); err != nil {
		return errors.New("完整备份中缺少数据库文件")
	}
	if err := Restore(db, dbPath); err != nil {
		return err
	}
	if err := copyRestoredData(staging, dataDir); err != nil {
		return err
	}
	return nil
}

func sealFullBackup(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, fullBackupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(fullBackupMagic)+len(salt)+len(nonce)+len(plain)+aead.Overhead())
	out = append(out, fullBackupMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, []byte(fullBackupMagic))
	return out, nil
}

func openFullBackup(data []byte, password string) ([]byte, error) {
	header := len(fullBackupMagic)
	if len(data) < header+saltLen+fullBackupNonceLen {
		return nil, errors.New("完整备份文件格式无效")
	}
	if string(data[:header]) != fullBackupMagic {
		return nil, errors.New("不是有效的完整备份文件")
	}
	salt := data[header : header+saltLen]
	nonceStart := header + saltLen
	nonceEnd := nonceStart + fullBackupNonceLen
	nonce := data[nonceStart:nonceEnd]
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) <= nonceEnd {
		return nil, errors.New("完整备份文件内容为空")
	}
	plain, err := aead.Open(nil, nonce, data[nonceEnd:], []byte(fullBackupMagic))
	if err != nil {
		return nil, errors.New("完整备份解密失败，请检查备份口令")
	}
	return plain, nil
}

func writeDataArchive(dataDir, snapshot, dest string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	if err := addFileToTar(tw, "domain-manager.db", snapshot); err != nil {
		return err
	}
	if dataDir != "" {
		base := filepath.Clean(dataDir)
		err = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == base {
				return nil
			}
			rel, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if rel == "tmp" || strings.HasPrefix(rel, "tmp/") {
				return filepath.SkipDir
			}
			name := entry.Name()
			if entry.IsDir() {
				return nil
			}
			if strings.HasSuffix(name, ".db") || strings.HasSuffix(name, ".db-wal") || strings.HasSuffix(name, ".db-shm") {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			return addFileToTar(tw, rel, path)
		})
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFileToTar(tw *tar.Writer, name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	header := &tar.Header{
		Name:    filepath.ToSlash(name),
		Mode:    int64(info.Mode().Perm()),
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func extractDataArchive(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return errors.New("完整备份压缩包损坏")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		target, err := safeArchivePath(dest, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg:
			total += header.Size
			if total > fullBackupMaxSize {
				return errors.New("完整备份解压后超过 4GB")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, header.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			// Symlinks, devices and other special entries are never restored.
			continue
		}
	}
	return nil
}

func copyRestoredData(staging, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "domain-manager.db" {
			continue
		}
		src := filepath.Join(staging, entry.Name())
		dst := filepath.Join(dataDir, entry.Name())
		if entry.IsDir() {
			if err := copyTree(src, dst); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		s := filepath.Join(src, entry.Name())
		d := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyTree(s, d); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(s, d); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(dst, info.Mode().Perm())
}

func safeArchivePath(root, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." {
		return root, nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("备份归档包含非法路径: %s", name)
	}
	target := filepath.Join(root, clean)
	prefix := root + string(filepath.Separator)
	if target != root && !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("备份归档包含非法路径: %s", name)
	}
	return target, nil
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
