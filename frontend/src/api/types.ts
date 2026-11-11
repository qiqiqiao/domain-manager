export interface User {
  id: number
  username: string
  role: string
  active: boolean
  must_change_password: boolean
  totp_enabled: boolean
  last_login_at?: string
  created_at: string
}

export interface Domain {
  id: number
  name: string
  registrar: string
  registered_at?: string
  expires_at?: string
  expiry_source: string
  expiry_locked: boolean
  days_remaining: number
  status: string
  monitor_enabled: boolean
  last_checked_at?: string
  last_error: string
  notes: string
  created_at: string
  updated_at: string
}

export interface Certificate {
  id: number
  domain_id?: number
  domain: string
  port: number
  sni: string
  skip_verify: boolean
  status: string
  https_status: string
  issuer: string
  subject: string
  serial_number: string
  not_before?: string
  not_after?: string
  days_remaining: number
  san: string[]
  chain_valid: boolean
  hostname_valid: boolean
  monitor_enabled: boolean
  managed: boolean
  auto_renew: boolean
  source: string
  order_id?: number
  has_private_key: boolean
  last_checked_at?: string
  last_error: string
  created_at: string
  updated_at: string
}

export interface Channel {
  id: number
  name: string
  type: string
  enabled: boolean
  config: Record<string, unknown>
  last_test_at?: string
  last_test_ok: boolean
  last_error: string
  created_at: string
  updated_at: string
}

export interface NotificationRule {
  id: number
  event: string
  channel_ids: number[]
  enabled: boolean
  dedup_hours: number
  description: string
}

export interface NotificationLog {
  id: number
  event: string
  subject: string
  channel_id: number
  channel_name: string
  title: string
  content: string
  status: string
  error: string
  attempts: number
  next_retry_at?: string
  sent_at?: string
  created_at: string
}

export interface MonitorLog {
  id: number
  kind: string
  target_id: number
  target: string
  action: string
  status: string
  message: string
  duration_ms: number
  details: string
  created_at: string
}

export interface Order {
  id: number
  primary_domain: string
  domains: string[]
  challenge_type: string
  dns_provider: string
  key_type: string
  email: string
  staging: boolean
  auto_renew: boolean
  status: string
  attempts: number
  max_attempts: number
  last_error: string
  logs: string
  cert_id?: number
  renewal_of?: number
  not_before?: string
  not_after?: string
  next_retry_at?: string
  started_at?: string
  completed_at?: string
  created_at: string
  updated_at: string
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface DashboardData {
  counts: Record<string, number>
  domain_status: { status: string; count: number }[]
  ssl_status: { status: string; count: number }[]
  trends: { dates: string[]; domain: number[]; ssl: number[]; failed: number[] }
  upcoming_domains: Domain[]
  upcoming_certs: Certificate[]
  recent_alerts: NotificationLog[]
}

export interface JobInfo {
  id: number
  key: string
  name: string
  cron: string
  enabled: boolean
  last_run_at?: string
  last_status: string
  last_error: string
  last_duration_ms: number
  next_run_at?: string
}

export interface JobRun {
  id: number
  job_key: string
  status: string
  message: string
  duration_ms: number
  started_at: string
  finished_at: string
}

export interface SystemStatus {
  version: string
  go_version: string
  os: string
  arch: string
  uptime_seconds: number
  started_at: string
  database_path: string
  database_size: number
  database: Record<string, number>
  domain_count: number
  certificate_count: number
  notification_channel_count: number
  acme_staging: boolean
  listen: string
}

export interface ACMEAccount {
  id: number
  email: string
  directory_url: string
  staging: boolean
  status: string
  last_used_at?: string
  created_at: string
}

export interface ApplyPayload {
  domains: string[]
  email: string
  challenge_type: string
  dns_provider: string
  dns_config: Record<string, string>
  key_type: string
  staging: boolean
  agree_tos: boolean
  auto_renew: boolean
}
