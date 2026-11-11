export const domainStatus: Record<string, { label: string; type: 'success' | 'warning' | 'danger' | 'info' | 'primary' }> = {
  normal: { label: '正常', type: 'success' },
  expiring: { label: '即将到期', type: 'warning' },
  expired: { label: '已过期', type: 'danger' },
  query_failed: { label: '查询失败', type: 'danger' },
  pending: { label: '待检测', type: 'info' },
}

export const certStatus: Record<string, { label: string; type: 'success' | 'warning' | 'danger' | 'info' | 'primary' }> = {
  normal: { label: '正常', type: 'success' },
  expiring: { label: '即将到期', type: 'warning' },
  expired: { label: '已过期', type: 'danger' },
  unreachable: { label: 'HTTPS 不可访问', type: 'danger' },
  invalid: { label: '证书异常', type: 'danger' },
  failed: { label: '检测失败', type: 'danger' },
  pending: { label: '待检测', type: 'info' },
}

export const httpsStatus: Record<string, string> = {
  ok: '正常',
  unreachable: '不可访问',
  server_error: '服务端错误',
  unknown: '待检测',
  not_checked: '未检测',
}

export const orderStatus: Record<string, { label: string; type: 'success' | 'warning' | 'danger' | 'info' | 'primary' }> = {
  pending: { label: '排队中', type: 'info' },
  running: { label: '处理中', type: 'warning' },
  valid: { label: '已签发', type: 'success' },
  failed: { label: '失败', type: 'danger' },
  renewed: { label: '已续期', type: 'primary' },
}

export const channelTypes: Record<string, string> = {
  telegram: 'Telegram',
  lark: 'Lark（国际版）',
  feishu: '飞书',
  dingtalk: '钉钉',
}

export const eventTypes: Record<string, string> = {
  domain_expiry: '域名到期提醒',
  ssl_expiry: 'SSL 证书到期提醒',
  certificate_issued: '证书申请成功',
  certificate_renewed: '证书续期成功',
  certificate_failed: '证书申请失败',
  system_error: '系统异常',
  recovery: '告警恢复',
}

export function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  })
}

export function daysClass(days: number): string {
  if (days < 0) return 'days-danger'
  if (days <= 7) return 'days-danger'
  if (days <= 30) return 'days-warning'
  return 'days-normal'
}

export function daysText(days: number): string {
  if (days < 0) return `已过期 ${Math.abs(days)} 天`
  if (days === 0) return '今天到期'
  return `${days} 天`
}

export function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

export function formatDuration(ms: number): string {
  if (!ms) return '—'
  if (ms < 1000) return `${ms} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export function parseCSVTemplate(): string {
  return '\ufeffdomain,expires_at,notes\nexample.com,2027-12-01,主域名\nwww.example.com,,\n'
}
