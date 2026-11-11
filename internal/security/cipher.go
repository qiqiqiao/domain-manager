package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Cipher provides authenticated encryption for secrets at rest.
type Cipher struct {
	mu   sync.RWMutex
	aead cipher.AEAD
}

func LoadOrCreateCipher(keyPath string) (*Cipher, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("创建密钥目录失败: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("读取加密密钥失败: %w", err)
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("生成加密密钥失败: %w", err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, fmt.Errorf("保存加密密钥失败: %w", err)
		}
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("加密密钥长度无效，应为 32 字节")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ReloadFromFile replaces the in-memory key after a full backup restore.
func (c *Cipher) ReloadFromFile(keyPath string) error {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读取加密密钥失败: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.aead = aead
	c.mu.Unlock()
	return nil
}

func (c *Cipher) Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, []byte(plain), nil)
	return "v1:" + base64.RawStdEncoding.EncodeToString(out), nil
}

func (c *Cipher) Decrypt(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, "v1:") {
		return "", errors.New("密文格式无效")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "v1:"))
	if err != nil {
		return "", err
	}
	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()
	if len(raw) < aead.NonceSize() {
		return "", errors.New("密文长度无效")
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("解密失败，密钥可能已变更")
	}
	return string(plain), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
