package database

import (
	"fmt"
	"path/filepath"
	"strings"

	"domain-manager/internal/logger"
	"domain-manager/internal/models"

	"gorm.io/gorm"
)

// queryColumns returns the column names produced by a SELECT statement. It is
// used instead of INSERT ... SELECT * so that backups created by older versions
// can be restored into schemas that gained columns.
func queryColumns(conn *gorm.DB, query string) ([]string, error) {
	rows, err := conn.Raw(query).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return rows.Columns()
}

func intersectColumns(live, backup []string) []string {
	backupSet := make(map[string]bool, len(backup))
	for _, name := range backup {
		backupSet[strings.ToLower(name)] = true
	}
	out := make([]string, 0, len(live))
	for _, name := range live {
		if backupSet[strings.ToLower(name)] {
			out = append(out, name)
		}
	}
	return out
}

func quoteColumns(columns []string) string {
	quoted := make([]string, len(columns))
	for i, name := range columns {
		quoted[i] = `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
	return strings.Join(quoted, ", ")
}

// RebasePaths rewrites managed certificate and ACME account paths to the
// current data directory. A database-only backup restored on another machine
// otherwise keeps paths from the old installation.
func RebasePaths(db *gorm.DB, dataDir string) error {
	base := filepath.Clean(dataDir)
	var certs []models.SSLCertificate
	if err := db.Where("cert_path <> '' OR key_path <> '' OR fullchain_path <> ''").Find(&certs).Error; err != nil {
		return err
	}
	for i := range certs {
		cert := &certs[i]
		dir := filepath.Join(base, "certs", fmt.Sprintf("%d", cert.ID))
		updates := map[string]any{}
		if cert.CertPath != "" {
			updates["cert_path"] = filepath.Join(dir, "cert.pem")
		}
		if cert.KeyPath != "" {
			updates["key_path"] = filepath.Join(dir, "privkey.pem")
		}
		if cert.FullchainPath != "" {
			updates["fullchain_path"] = filepath.Join(dir, "fullchain.pem")
		}
		if len(updates) > 0 {
			if err := db.Model(&models.SSLCertificate{}).Where("id = ?", cert.ID).Updates(updates).Error; err != nil {
				return err
			}
		}
	}

	var accounts []models.ACMEAccount
	if err := db.Where("key_path <> ''").Find(&accounts).Error; err != nil {
		return err
	}
	for i := range accounts {
		account := &accounts[i]
		name := filepath.Base(filepath.Clean(account.KeyPath))
		if name == "" || name == "." || name == string(filepath.Separator) {
			continue
		}
		path := filepath.Join(base, "acme", "accounts", name)
		if err := db.Model(&models.ACMEAccount{}).Where("id = ?", account.ID).Update("key_path", path).Error; err != nil {
			return err
		}
	}
	logger.L().Info("已按当前数据目录重写证书与 ACME 账号路径", "data_dir", base)
	return nil
}
