<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">证书申请</h1>
        <p class="page-subtitle">通过 ACME 协议申请 Let's Encrypt 证书。默认使用 Staging 测试环境，确认流程无误后再切换生产环境。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="Refresh" :loading="ordersLoading" @click="loadOrders">刷新订单</el-button>
      </div>
    </div>

    <div class="apply-layout">
      <div class="panel apply-form-panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">创建证书订单</h3>
            <p class="panel-subtitle">支持单域名、多域名 SAN 与泛域名证书</p>
          </div>
          <el-tag :type="form.staging ? 'warning' : 'danger'" effect="plain">
            {{ form.staging ? 'STAGING 测试环境' : 'PRODUCTION 生产环境' }}
          </el-tag>
        </div>
        <div class="panel-body">
          <el-form ref="formRef" :model="form" :rules="rules" label-position="top">
            <el-form-item label="证书域名" prop="domainsText">
              <el-input
                v-model="form.domainsText"
                type="textarea"
                :rows="4"
                placeholder="example.com&#10;www.example.com&#10;*.example.com"
              />
              <div class="form-hint">每行一个域名，也支持逗号分隔。通配符 <code>*.example.com</code> 必须使用 DNS-01，并建议同时添加根域名。</div>
            </el-form-item>

            <div class="form-grid">
              <el-form-item label="ACME 账号邮箱" prop="email">
                <el-input v-model="form.email" placeholder="admin@example.com" />
              </el-form-item>
              <el-form-item label="证书密钥类型">
                <el-select v-model="form.key_type" style="width: 100%">
                  <el-option label="RSA 2048（兼容性最佳）" value="rsa2048" />
                  <el-option label="RSA 4096" value="rsa4096" />
                  <el-option label="ECDSA P-256" value="ec256" />
                  <el-option label="ECDSA P-384" value="ec384" />
                </el-select>
              </el-form-item>
            </div>

            <el-form-item label="验证方式">
              <div class="challenge-grid">
                <button type="button" class="challenge-card" :class="{ active: form.challenge_type === 'http-01' }" @click="form.challenge_type = 'http-01'">
                  <el-icon><Connection /></el-icon>
                  <strong>HTTP-01</strong>
                  <span>通过公网 80 端口验证域名控制权</span>
                </button>
                <button type="button" class="challenge-card" :class="{ active: form.challenge_type === 'dns-01' }" @click="form.challenge_type = 'dns-01'">
                  <el-icon><Key /></el-icon>
                  <strong>DNS-01</strong>
                  <span>通过 DNS TXT 记录验证，支持泛域名</span>
                </button>
              </div>
            </el-form-item>

            <div v-if="form.challenge_type === 'http-01'" class="alert-box warn">
              HTTP-01 由 Let's Encrypt 从公网访问 <code>http://域名/.well-known/acme-challenge/</code>。
              使用内置 Standalone 模式时本机必须能监听 80 端口；使用 Webroot 模式时必须由现有 Web 服务器提供该目录。
              如服务器位于 NAT/负载均衡后，请提前配置 80 端口转发。
            </div>

            <template v-else>
              <el-form-item label="DNS 服务商">
                <el-select v-model="form.dns_provider" style="width: 100%" @change="resetDNSConfig">
                  <el-option label="Cloudflare" value="cloudflare" />
                  <el-option label="DNSPod / 腾讯云" value="dnspod" />
                  <el-option label="阿里云 DNS" value="alidns" />
                </el-select>
              </el-form-item>
              <div class="form-grid">
                <template v-if="form.dns_provider === 'cloudflare'">
                  <el-form-item label="Cloudflare API Token" class="span-2" prop="dns_config.api_token">
                    <el-input v-model="form.dns_config.api_token" type="password" show-password placeholder="需要 Zone:Read 与 DNS:Edit 权限" />
                  </el-form-item>
                  <el-form-item label="Zone ID（可选）">
                    <el-input v-model="form.dns_config.zone_id" placeholder="留空自动查询" />
                  </el-form-item>
                  <el-form-item label="DNS 区域（可选）">
                    <el-input v-model="form.dns_config.zone" placeholder="默认自动推导 eTLD+1" />
                  </el-form-item>
                </template>
                <template v-else-if="form.dns_provider === 'dnspod'">
                  <el-form-item label="SecretId">
                    <el-input v-model="form.dns_config.secret_id" placeholder="腾讯云 SecretId" />
                  </el-form-item>
                  <el-form-item label="SecretKey">
                    <el-input v-model="form.dns_config.secret_key" type="password" show-password placeholder="腾讯云 SecretKey" />
                  </el-form-item>
                  <el-form-item label="Region（可选）">
                    <el-input v-model="form.dns_config.region" placeholder="例如 ap-guangzhou" />
                  </el-form-item>
                  <el-form-item label="DNS 区域（可选）">
                    <el-input v-model="form.dns_config.zone" placeholder="默认自动推导" />
                  </el-form-item>
                </template>
                <template v-else>
                  <el-form-item label="AccessKeyId">
                    <el-input v-model="form.dns_config.access_key_id" placeholder="阿里云 AccessKeyId" />
                  </el-form-item>
                  <el-form-item label="AccessKeySecret">
                    <el-input v-model="form.dns_config.access_key_secret" type="password" show-password placeholder="阿里云 AccessKeySecret" />
                  </el-form-item>
                  <el-form-item label="DNS 区域（可选）" class="span-2">
                    <el-input v-model="form.dns_config.zone" placeholder="默认自动推导，例如 example.com" />
                  </el-form-item>
                </template>
              </div>
              <div class="alert-box warn">
                DNS-01 会真实调用 DNS 服务商 API 创建 `_acme-challenge` TXT 记录，等待公网 DNS 生效后清理。
                请确保 API 凭据具备目标区域的 DNS 编辑权限。凭据将加密保存，不会在页面回显。
              </div>
            </template>

            <div class="options-panel">
              <div class="option-row">
                <div>
                  <strong>Let's Encrypt Staging（推荐）</strong>
                  <span>使用测试环境验证流程，避免消耗生产证书与触发限流。测试证书不被浏览器信任。</span>
                </div>
                <el-switch v-model="form.staging" />
              </div>
              <div class="option-row">
                <div>
                  <strong>到期前自动续期</strong>
                  <span>签发成功后写入证书管理，任务调度器将在到期前自动创建续期订单。</span>
                </div>
                <el-switch v-model="form.auto_renew" />
              </div>
            </div>

            <el-checkbox v-model="form.agree_tos" class="tos-check">
              我确认域名解析、HTTP/DNS 验证条件已满足，并同意 ACME 服务商的服务条款。
            </el-checkbox>

            <el-button class="submit-btn" type="primary" size="large" :loading="submitting" @click="submit">
              <el-icon><Promotion /></el-icon>
              提交证书申请
            </el-button>
          </el-form>
        </div>
      </div>

      <aside class="side-column">
        <div class="panel info-card">
          <div class="info-icon"><el-icon><Lock /></el-icon></div>
          <h3>申请前检查清单</h3>
          <ul>
            <li>域名已正确添加 A / AAAA 记录</li>
            <li>HTTP-01：公网可访问 80 端口或 Webroot 可被外部访问</li>
            <li>DNS-01：DNS API 凭据具有 TXT 记录编辑权限</li>
            <li>泛域名必须使用 DNS-01</li>
            <li>先在 Staging 验证通过，再切换生产环境</li>
          </ul>
        </div>
        <div class="panel info-card">
          <div class="info-icon amber"><el-icon><Warning /></el-icon></div>
          <h3>关于自动部署</h3>
          <p>
            系统不会自动修改 Nginx / Apache 配置。证书签发后可下载 PEM 文件，或在「系统设置」中配置部署目录与部署脚本，
            由系统完成安全文件落盘并触发脚本。
          </p>
        </div>
        <div class="panel info-card">
          <div class="info-icon blue"><el-icon><Key /></el-icon></div>
          <h3>安全说明</h3>
          <p>
            证书私钥仅以 0600 权限保存在服务器本地，不会出现在列表、日志或普通 API 响应中。
            下载私钥需要管理员明确确认。
          </p>
        </div>
      </aside>
    </div>

    <div class="panel section-gap">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">最近证书订单</h3>
          <p class="panel-subtitle">订单状态与 ACME 申请日志</p>
        </div>
        <el-tag v-if="polling" type="warning" effect="plain" size="small">自动刷新中</el-tag>
      </div>
      <el-table v-loading="ordersLoading" :data="orders" class="dm-table" empty-text="暂无证书订单">
        <el-table-column prop="id" label="订单" width="78">
          <template #default="{ row }"><span class="mono">#{{ row.id }}</span></template>
        </el-table-column>
        <el-table-column label="域名" min-width="220">
          <template #default="{ row }">
            <div class="order-domains">
              <span v-for="domain in row.domains.slice(0, 2)" :key="domain" class="mono">{{ domain }}</span>
              <span v-if="row.domains.length > 2" class="muted">+{{ row.domains.length - 2 }} 个</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="验证" width="95">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.challenge_type }}</el-tag>
            <span v-if="row.dns_provider" class="provider">{{ row.dns_provider }}</span>
          </template>
        </el-table-column>
        <el-table-column label="环境" width="95">
          <template #default="{ row }">
            <el-tag size="small" :type="row.staging ? 'warning' : 'danger'" effect="plain">{{ row.staging ? 'Staging' : '生产' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="105">
          <template #default="{ row }">
            <el-tag :type="orderStatus[row.status]?.type || 'info'" size="small" effect="light">{{ orderStatus[row.status]?.label || row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="有效期至" width="120">
          <template #default="{ row }">{{ formatDate(row.not_after) }}</template>
        </el-table-column>
        <el-table-column label="尝试" width="70" align="center">
          <template #default="{ row }">{{ row.attempts }}/{{ row.max_attempts }}</template>
        </el-table-column>
        <el-table-column label="创建时间" width="165">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="showLogs(row)">日志</el-button>
            <el-button v-if="row.status === 'failed'" link type="warning" @click="retry(row)">重试</el-button>
            <el-button v-if="row.cert_id" link type="primary" @click="router.push('/certificates')">查看证书</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="logsVisible" :title="`订单 #${activeOrder?.id || ''} 申请日志`" width="760px" append-to-body>
      <div v-if="activeOrder" class="order-summary">
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="主域名">{{ activeOrder.primary_domain }}</el-descriptions-item>
          <el-descriptions-item label="状态">{{ orderStatus[activeOrder.status]?.label || activeOrder.status }}</el-descriptions-item>
          <el-descriptions-item label="域名列表">{{ activeOrder.domains.join(', ') }}</el-descriptions-item>
          <el-descriptions-item label="错误">{{ activeOrder.last_error || '—' }}</el-descriptions-item>
        </el-descriptions>
      </div>
      <pre class="order-log">{{ activeOrder?.logs || '暂无日志' }}</pre>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import type { FormInstance, FormRules } from 'element-plus'
import { Connection, Key, Lock, Promotion, Refresh, Warning } from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { ApplyPayload, Order } from '@/api/types'
import { formatDate, formatDateTime, orderStatus } from '@/utils/status'

const route = useRoute()
const router = useRouter()
const formRef = ref<FormInstance>()
const submitting = ref(false)
const orders = ref<Order[]>([])
const ordersLoading = ref(false)
const logsVisible = ref(false)
const activeOrder = ref<Order | null>(null)
let timer: number | undefined

const form = reactive({
  domainsText: typeof route.query.domain === 'string' ? route.query.domain : '',
  email: '',
  challenge_type: 'http-01',
  dns_provider: 'cloudflare',
  dns_config: {} as Record<string, string>,
  key_type: 'rsa2048',
  staging: true,
  auto_renew: true,
  agree_tos: false,
})

const rules: FormRules = {
  domainsText: [{ required: true, message: '请输入至少一个域名', trigger: 'blur' }],
  email: [
    { required: true, message: '请输入 ACME 账号邮箱', trigger: 'blur' },
    { type: 'email', message: '邮箱格式无效', trigger: 'blur' },
  ],
}

const domainList = computed(() =>
  form.domainsText.split(/[\n,，\s]+/).map((d) => d.trim()).filter(Boolean),
)
const polling = computed(() => orders.value.some((order) => ['pending', 'running'].includes(order.status)))

function resetDNSConfig() {
  form.dns_config = {}
}

async function submit() {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  if (!form.agree_tos) {
    ElMessage.warning('请先勾选确认项')
    return
  }
  const domains = domainList.value
  if (!domains.length) {
    ElMessage.warning('请填写证书域名')
    return
  }
  if (domains.some((d) => d.startsWith('*.')) && form.challenge_type !== 'dns-01') {
    ElMessage.warning('通配符证书必须使用 DNS-01 验证')
    form.challenge_type = 'dns-01'
    return
  }
  if (form.challenge_type === 'dns-01') {
    const required = form.dns_provider === 'cloudflare'
      ? ['api_token']
      : form.dns_provider === 'dnspod' ? ['secret_id', 'secret_key'] : ['access_key_id', 'access_key_secret']
    if (required.some((key) => !String(form.dns_config[key] || '').trim())) {
      ElMessage.warning('请填写完整的 DNS API 凭据')
      return
    }
  }
  if (!form.staging) {
    try {
      await ElMessageBox.confirm(
        "当前将向 Let's Encrypt 生产环境申请真实可信证书。请确认域名验证条件已满足，否则可能触发 CA 限流。继续提交吗？",
        '生产环境申请确认',
        { confirmButtonText: '确认提交', cancelButtonText: '返回检查', type: 'warning' },
      )
    } catch {
      return
    }
  }
  const payload: ApplyPayload = {
    domains,
    email: form.email.trim(),
    challenge_type: form.challenge_type,
    dns_provider: form.challenge_type === 'dns-01' ? form.dns_provider : '',
    dns_config: form.challenge_type === 'dns-01' ? { ...form.dns_config } : {},
    key_type: form.key_type,
    staging: form.staging,
    agree_tos: form.agree_tos,
    auto_renew: form.auto_renew,
  }
  submitting.value = true
  try {
    const order = await api.post<Order>('/certificates/apply', payload)
    ElMessage.success(`证书订单 #${order.id} 已创建，正在后台处理`)
    form.agree_tos = false
    await loadOrders()
  } catch (error) {
    showError(error)
  } finally {
    submitting.value = false
  }
}

async function loadOrders() {
  ordersLoading.value = true
  try {
    orders.value = await api.get<Order[]>('/orders')
    if (activeOrder.value) {
      activeOrder.value = orders.value.find((item) => item.id === activeOrder.value?.id) || activeOrder.value
    }
  } catch (error) {
    showError(error)
  } finally {
    ordersLoading.value = false
  }
}

function showLogs(order: Order) {
  activeOrder.value = order
  logsVisible.value = true
}

async function retry(order: Order) {
  try {
    await api.post(`/orders/${order.id}/retry`)
    ElMessage.success('已重新提交订单')
    loadOrders()
  } catch (error) {
    showError(error)
  }
}

async function loadDefaults() {
  try {
    const data = await api.get<{ settings: Record<string, string> }>('/settings')
    if (data.settings.acme_email && !form.email) form.email = data.settings.acme_email
    if (data.settings.acme_staging !== undefined) form.staging = data.settings.acme_staging !== 'false'
    if (data.settings.acme_key_type) form.key_type = data.settings.acme_key_type
    if (data.settings.acme_default_dns_provider) form.dns_provider = data.settings.acme_default_dns_provider
    if (typeof route.query.domain === 'string') form.domainsText = route.query.domain
  } catch {
    // Settings are optional for rendering the form.
  }
}

onMounted(async () => {
  await Promise.all([loadDefaults(), loadOrders()])
  timer = window.setInterval(() => {
    if (polling.value) loadOrders()
  }, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped>
.apply-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.7fr) minmax(300px, 0.8fr);
  gap: 16px;
  align-items: start;
}
.apply-form-panel {
  min-width: 0;
}
.side-column {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.info-card {
  padding: 20px;
}
.info-icon {
  width: 38px;
  height: 38px;
  border-radius: 11px;
  display: grid;
  place-items: center;
  background: var(--dm-primary-soft);
  color: var(--dm-primary);
  font-size: 18px;
  margin-bottom: 14px;
}
.info-icon.amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
.info-icon.blue { background: rgba(14, 165, 233, 0.1); color: #0ea5e9; }
.info-card h3 {
  font-size: 14px;
  margin: 0 0 12px;
}
.info-card ul {
  margin: 0;
  padding-left: 18px;
  color: var(--dm-text-secondary);
  font-size: 12.5px;
  line-height: 2;
}
.info-card p {
  margin: 0;
  color: var(--dm-text-secondary);
  font-size: 12.5px;
  line-height: 1.8;
}
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.span-2 {
  grid-column: span 2;
}
.challenge-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  width: 100%;
}
.challenge-card {
  text-align: left;
  border: 1px solid var(--dm-border);
  background: var(--dm-panel);
  border-radius: 12px;
  padding: 15px;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 5px;
  transition: all 0.18s;
  color: var(--dm-text);
  font-family: inherit;
}
.challenge-card:hover {
  border-color: var(--dm-primary);
}
.challenge-card.active {
  border-color: var(--dm-primary);
  background: var(--dm-primary-soft);
  box-shadow: 0 0 0 3px rgba(15, 157, 138, 0.08);
}
.challenge-card .el-icon {
  color: var(--dm-primary);
  font-size: 20px;
  margin-bottom: 3px;
}
.challenge-card strong {
  font-size: 13.5px;
}
.challenge-card span {
  font-size: 11px;
  color: var(--dm-text-muted);
  line-height: 1.5;
}
.options-panel {
  border: 1px solid var(--dm-border);
  border-radius: 12px;
  overflow: hidden;
  margin: 4px 0 16px;
}
.option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 15px 16px;
  border-bottom: 1px solid var(--dm-border);
}
.option-row:last-child { border-bottom: 0; }
.option-row div {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.option-row strong { font-size: 12.5px; }
.option-row span {
  font-size: 11.5px;
  color: var(--dm-text-muted);
  line-height: 1.55;
}
.tos-check {
  display: block;
  margin-bottom: 16px;
  white-space: normal;
  height: auto;
}
.tos-check :deep(.el-checkbox__label) {
  font-size: 12px;
  line-height: 1.6;
  white-space: normal;
}
.submit-btn {
  width: 100%;
  height: 46px;
  font-size: 14px;
}
.order-domains {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.order-domains span {
  font-size: 11.5px;
}
.provider {
  display: block;
  color: var(--dm-text-muted);
  font-size: 10px;
  margin-top: 3px;
}
.order-summary {
  margin-bottom: 14px;
}
.order-log {
  margin: 0;
  background: #0b1220;
  color: #cbd5e1;
  border-radius: 12px;
  padding: 16px;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.7;
  max-height: 420px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}
@media (max-width: 1100px) {
  .apply-layout {
    grid-template-columns: 1fr;
  }
  .side-column {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}
@media (max-width: 760px) {
  .form-grid, .challenge-grid, .side-column {
    grid-template-columns: 1fr;
  }
  .span-2 { grid-column: span 1; }
}
</style>
