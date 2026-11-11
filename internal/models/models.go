package models

import "time"

const (
	DomainStatusPending     = "pending"
	DomainStatusNormal      = "normal"
	DomainStatusExpiring    = "expiring"
	DomainStatusExpired     = "expired"
	DomainStatusQueryFailed = "query_failed"

	CertStatusPending     = "pending"
	CertStatusNormal      = "normal"
	CertStatusExpiring    = "expiring"
	CertStatusExpired     = "expired"
	CertStatusUnreachable = "unreachable"
	CertStatusInvalid     = "invalid"
	CertStatusFailed      = "failed"

	EventDomainExpiry = "domain_expiry"
	EventSSLExpiry    = "ssl_expiry"
	EventCertIssued   = "certificate_issued"
	EventCertRenewed  = "certificate_renewed"
	EventCertFailed   = "certificate_failed"
	EventSystemError  = "system_error"
	EventRecovery     = "recovery"

	ChannelTelegram = "telegram"
	ChannelLark     = "lark"
	ChannelFeishu   = "feishu"
	ChannelDingTalk = "dingtalk"
)

// Domain is a monitored registered domain.
type Domain struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	Name           string     `gorm:"uniqueIndex;size:253;not null" json:"name"`
	Registrar      string     `gorm:"size:255" json:"registrar"`
	RegisteredAt   *time.Time `json:"registered_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	ExpirySource   string     `gorm:"size:20;default:'unknown'" json:"expiry_source"`
	ExpiryLocked   bool       `gorm:"not null;default:false" json:"expiry_locked"`
	DaysRemaining  int        `json:"days_remaining"`
	Status         string     `gorm:"index;size:32;not null;default:'pending'" json:"status"`
	MonitorEnabled bool       `gorm:"not null;default:true" json:"monitor_enabled"`
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	LastError      string     `gorm:"type:text" json:"last_error"`
	Notes          string     `gorm:"type:text" json:"notes"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// SSLCertificate represents a monitored HTTPS endpoint. Managed certificates
// also point at the local PEM files produced by the ACME module.
type SSLCertificate struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	DomainID       *uint      `gorm:"index" json:"domain_id"`
	Domain         string     `gorm:"size:253;not null;uniqueIndex:idx_cert_endpoint" json:"domain"`
	Port           int        `gorm:"not null;default:443;uniqueIndex:idx_cert_endpoint" json:"port"`
	SNI            string     `gorm:"size:253" json:"sni"`
	SkipVerify     bool       `gorm:"not null;default:false" json:"skip_verify"`
	Status         string     `gorm:"index;size:32;not null;default:'pending'" json:"status"`
	HTTPSStatus    string     `gorm:"column:https_status;size:32;default:'unknown'" json:"https_status"`
	Issuer         string     `gorm:"size:255" json:"issuer"`
	Subject        string     `gorm:"size:255" json:"subject"`
	SerialNumber   string     `gorm:"size:128" json:"serial_number"`
	NotBefore      *time.Time `json:"not_before"`
	NotAfter       *time.Time `json:"not_after"`
	DaysRemaining  int        `json:"days_remaining"`
	SAN            string     `gorm:"type:text" json:"san"`
	ChainValid     bool       `json:"chain_valid"`
	HostnameValid  bool       `json:"hostname_valid"`
	MonitorEnabled bool       `gorm:"not null;default:true" json:"monitor_enabled"`
	Managed        bool       `gorm:"not null;default:false" json:"managed"`
	AutoRenew      bool       `gorm:"not null;default:false" json:"auto_renew"`
	Source         string     `gorm:"size:20;default:'monitor'" json:"source"`
	OrderID        *uint      `gorm:"index" json:"order_id"`
	CertPath       string     `gorm:"size:500" json:"-"`
	KeyPath        string     `gorm:"size:500" json:"-"`
	FullchainPath  string     `gorm:"size:500" json:"-"`
	HasPrivateKey  bool       `gorm:"-" json:"has_private_key"`
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	LastError      string     `gorm:"type:text" json:"last_error"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// NotificationChannel stores an encrypted channel configuration.
type NotificationChannel struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	Name            string     `gorm:"size:100;not null" json:"name"`
	Type            string     `gorm:"size:32;not null;index" json:"type"`
	ConfigEncrypted string     `gorm:"type:text;not null" json:"-"`
	Enabled         bool       `gorm:"not null;default:true" json:"enabled"`
	LastTestAt      *time.Time `json:"last_test_at"`
	LastTestOK      bool       `json:"last_test_ok"`
	LastError       string     `gorm:"type:text" json:"last_error"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// NotificationRule binds an event to one or more notification channels.
type NotificationRule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Event       string    `gorm:"uniqueIndex;size:64;not null" json:"event"`
	ChannelIDs  string    `gorm:"type:text" json:"-"` // JSON []uint
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`
	DedupHours  int       `gorm:"not null;default:24" json:"dedup_hours"`
	Description string    `gorm:"size:255" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NotificationLog struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Event       string     `gorm:"size:64;index" json:"event"`
	Subject     string     `gorm:"size:255;index" json:"subject"`
	ChannelID   uint       `gorm:"index" json:"channel_id"`
	ChannelName string     `gorm:"size:100" json:"channel_name"`
	DedupKey    string     `gorm:"size:255;index" json:"dedup_key"`
	Title       string     `gorm:"size:255" json:"title"`
	Content     string     `gorm:"type:text" json:"content"`
	Status      string     `gorm:"size:20;index" json:"status"` // success, failed, pending
	Error       string     `gorm:"type:text" json:"error"`
	Attempts    int        `gorm:"not null;default:0" json:"attempts"`
	NextRetryAt *time.Time `json:"next_retry_at"`
	SentAt      *time.Time `json:"sent_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type MonitorLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Kind       string    `gorm:"size:20;index" json:"kind"` // domain, ssl, acme, system
	TargetID   uint      `gorm:"index" json:"target_id"`
	Target     string    `gorm:"size:255;index" json:"target"`
	Action     string    `gorm:"size:64" json:"action"`
	Status     string    `gorm:"size:20;index" json:"status"` // success, failed, info
	Message    string    `gorm:"type:text" json:"message"`
	DurationMS int64     `json:"duration_ms"`
	Details    string    `gorm:"type:text" json:"details"`
	CreatedAt  time.Time `gorm:"index" json:"created_at"`
}

type ACMEAccount struct {
	ID               uint       `gorm:"primaryKey" json:"id"`
	Email            string     `gorm:"size:255;not null;uniqueIndex:idx_acme_account" json:"email"`
	DirectoryURL     string     `gorm:"size:500;not null;uniqueIndex:idx_acme_account" json:"directory_url"`
	Staging          bool       `json:"staging"`
	KeyPath          string     `gorm:"size:500" json:"-"`
	RegistrationJSON string     `gorm:"type:text" json:"-"`
	Status           string     `gorm:"size:32;default:'active'" json:"status"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type CertificateOrder struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	PrimaryDomain string     `gorm:"size:253;not null;index" json:"primary_domain"`
	DomainsJSON   string     `gorm:"type:text;not null" json:"-"`
	ChallengeType string     `gorm:"size:20;not null" json:"challenge_type"`
	DNSProvider   string     `gorm:"size:32" json:"dns_provider"`
	DNSConfigEnc  string     `gorm:"type:text" json:"-"`
	KeyType       string     `gorm:"size:20;default:'rsa2048'" json:"key_type"`
	Email         string     `gorm:"size:255" json:"email"`
	Staging       bool       `gorm:"not null;default:true" json:"staging"`
	AutoRenew     bool       `gorm:"not null;default:true" json:"auto_renew"`
	Status        string     `gorm:"size:32;not null;default:'pending';index" json:"status"`
	Attempts      int        `gorm:"not null;default:0" json:"attempts"`
	MaxAttempts   int        `gorm:"not null;default:3" json:"max_attempts"`
	LastError     string     `gorm:"type:text" json:"last_error"`
	Logs          string     `gorm:"type:text" json:"logs"`
	CertID        *uint      `gorm:"index" json:"cert_id"`
	RenewalOf     *uint      `gorm:"index" json:"renewal_of"`
	NotBefore     *time.Time `json:"not_before"`
	NotAfter      *time.Time `json:"not_after"`
	NextRetryAt   *time.Time `json:"next_retry_at"`
	StartedAt     *time.Time `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type AlertState struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	SubjectType    string     `gorm:"size:20;not null;uniqueIndex:idx_alert_subject" json:"subject_type"`
	SubjectID      uint       `gorm:"not null;uniqueIndex:idx_alert_subject" json:"subject_id"`
	AlertType      string     `gorm:"size:32;not null;uniqueIndex:idx_alert_subject" json:"alert_type"`
	Active         bool       `gorm:"not null;default:false" json:"active"`
	LastThreshold  int        `json:"last_threshold"`
	LastExpiry     *time.Time `json:"last_expiry"`
	LastNotifiedAt *time.Time `json:"last_notified_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type SystemSetting struct {
	Key       string    `gorm:"primaryKey;size:100" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ScheduledJob struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	Key            string     `gorm:"uniqueIndex;size:64;not null" json:"key"`
	Name           string     `gorm:"size:100;not null" json:"name"`
	Cron           string     `gorm:"size:100;not null" json:"cron"`
	Enabled        bool       `gorm:"not null;default:true" json:"enabled"`
	LastRunAt      *time.Time `json:"last_run_at"`
	LastStatus     string     `gorm:"size:20" json:"last_status"`
	LastError      string     `gorm:"type:text" json:"last_error"`
	LastDurationMS int64      `json:"last_duration_ms"`
	NextRunAt      *time.Time `json:"next_run_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type JobRun struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	JobKey     string    `gorm:"size:64;index" json:"job_key"`
	Status     string    `gorm:"size:20;index" json:"status"`
	Message    string    `gorm:"type:text" json:"message"`
	DurationMS int64     `json:"duration_ms"`
	StartedAt  time.Time `gorm:"index" json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type User struct {
	ID                 uint       `gorm:"primaryKey" json:"id"`
	Username           string     `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash       string     `gorm:"size:255;not null" json:"-"`
	Role               string     `gorm:"size:20;default:'admin'" json:"role"`
	Active             bool       `gorm:"not null;default:true" json:"active"`
	MustChangePassword bool       `gorm:"not null;default:false" json:"must_change_password"`
	TOTPSecret         string     `gorm:"size:255" json:"-"`
	TOTPEnabled        bool       `gorm:"not null;default:false" json:"totp_enabled"`
	TOTPRecoveryCodes  string     `gorm:"type:text" json:"-"`
	TOTPLastUsedStep   int64      `gorm:"not null;default:0" json:"-"`
	LastLoginAt        *time.Time `json:"last_login_at"`
	FailedAttempts     int        `gorm:"not null;default:0" json:"-"`
	LockedUntil        *time.Time `json:"-"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type SchemaMigration struct {
	Version   string `gorm:"primaryKey;size:64"`
	AppliedAt time.Time
}
