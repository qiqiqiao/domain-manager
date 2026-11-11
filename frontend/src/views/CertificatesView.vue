<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">SSL 证书管理</h1>
        <p class="page-subtitle">检测 HTTPS 可访问性、证书链、域名匹配与到期时间，支持 ACME 托管证书续期。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="DocumentAdd" type="primary" plain @click="router.push('/apply')">申请证书</el-button>
        <el-button :icon="Plus" @click="openCreate">添加监控</el-button>
      </div>
    </div>

    <div class="panel">
      <div class="toolbar">
        <div class="toolbar-left">
          <el-input
            v-model="filters.search"
            placeholder="搜索域名或颁发机构"
            clearable
            style="width: 250px"
            :prefix-icon="Search"
            @keyup.enter="applySearch"
            @clear="applySearch"
          />
          <el-select v-model="filters.status" placeholder="全部状态" clearable style="width: 155px" @change="applySearch">
            <el-option v-for="(item, key) in certStatus" :key="key" :label="item.label" :value="key" />
          </el-select>
          <el-select v-model="filters.managed" placeholder="证书来源" clearable style="width: 140px" @change="applySearch">
            <el-option label="ACME 托管" value="true" />
            <el-option label="仅监控" value="false" />
          </el-select>
          <el-button :icon="Search" @click="applySearch">查询</el-button>
        </div>
        <div class="toolbar-right">
          <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
          <el-button :icon="Aim" :loading="checkingAll" @click="checkAll">检测全部</el-button>
        </div>
      </div>

      <div class="table-wrap">
        <el-table v-loading="loading" :data="items" class="dm-table" row-key="id" empty-text="暂无证书监控">
          <el-table-column label="域名端点" min-width="210" fixed="left">
            <template #default="{ row }">
              <div class="endpoint-cell">
                <div class="endpoint-avatar" :class="{ managed: row.managed }">
                  <el-icon><Lock /></el-icon>
                </div>
                <div class="endpoint-info">
                  <span class="endpoint-name">{{ row.domain }}:{{ row.port }}</span>
                  <span class="endpoint-meta">
                    <el-tag v-if="row.managed" size="small" type="success" effect="plain">ACME</el-tag>
                    <el-tag v-if="row.skip_verify" size="small" type="warning" effect="plain">跳过校验</el-tag>
                    <span v-if="row.sni">SNI: {{ row.sni }}</span>
                  </span>
                </div>
                <el-tooltip v-if="row.last_error" :content="row.last_error" placement="top" popper-class="error-tooltip">
                  <el-icon class="error-icon"><WarningFilled /></el-icon>
                </el-tooltip>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="HTTPS" width="105">
            <template #default="{ row }">
              <el-tag :type="row.https_status === 'ok' ? 'success' : row.https_status === 'server_error' ? 'warning' : 'danger'" effect="plain" size="small">
                {{ httpsStatus[row.https_status] || row.https_status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="证书颁发机构" min-width="165">
            <template #default="{ row }">
              <div class="issuer-cell">
                <span>{{ row.issuer || '—' }}</span>
                <span v-if="row.not_after" class="verify-badges">
                  <el-tooltip :content="row.chain_valid ? '证书链校验通过' : '证书链无效或不受信任'">
                    <el-icon :class="row.chain_valid ? 'ok' : 'bad'"><CircleCheckFilled v-if="row.chain_valid" /><WarningFilled v-else /></el-icon>
                  </el-tooltip>
                  <el-tooltip :content="row.hostname_valid ? '证书域名匹配' : '证书域名不匹配'">
                    <el-tag size="small" :type="row.hostname_valid ? 'success' : 'danger'" effect="plain">{{ row.hostname_valid ? 'MATCH' : 'MISMATCH' }}</el-tag>
                  </el-tooltip>
                </span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="生效时间" width="118">
            <template #default="{ row }">{{ formatDate(row.not_before) }}</template>
          </el-table-column>
          <el-table-column label="到期时间" width="118">
            <template #default="{ row }">{{ formatDate(row.not_after) }}</template>
          </el-table-column>
          <el-table-column label="剩余" width="110">
            <template #default="{ row }">
              <span v-if="row.not_after" :class="daysClass(row.days_remaining)">{{ daysText(row.days_remaining) }}</span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column label="证书状态" width="120">
            <template #default="{ row }">
              <el-tag :type="certStatus[row.status]?.type || 'info'" effect="light">
                {{ certStatus[row.status]?.label || row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="自动续期" width="90" align="center">
            <template #default="{ row }">
              <el-switch
                v-if="row.managed"
                :model-value="row.auto_renew"
                size="small"
                @change="(value: boolean) => toggleAutoRenew(row, value)"
              />
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column label="最后检测" width="165">
            <template #default="{ row }">{{ formatDateTime(row.last_checked_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="210" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" :loading="rowChecking === row.id" @click="checkOne(row)">检测</el-button>
              <el-button v-if="row.managed" link type="primary" @click="renew(row)">续期</el-button>
              <el-dropdown trigger="click" @command="(cmd: string) => handleCommand(cmd, row)">
                <el-button link type="primary">更多<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="detail" :icon="View">查看证书详情</el-dropdown-item>
                    <el-dropdown-item v-if="row.has_private_key" command="download-fullchain" :icon="Download" divided>下载 fullchain.pem</el-dropdown-item>
                    <el-dropdown-item v-if="row.has_private_key" command="download-cert" :icon="Download">下载 cert.pem</el-dropdown-item>
                    <el-dropdown-item v-if="row.has_private_key" command="download-privkey" :icon="Key">
                      下载 privkey.pem
                    </el-dropdown-item>
                    <el-dropdown-item v-if="row.managed" command="deploy" :icon="Upload">部署证书文件</el-dropdown-item>
                    <el-dropdown-item command="apply" :icon="DocumentAdd" divided>用此域名申请</el-dropdown-item>
                    <el-dropdown-item command="edit" :icon="Edit" divided>编辑监控</el-dropdown-item>
                    <el-dropdown-item command="delete" :icon="Delete" style="color: #ef4444">删除</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
        </el-table>
      </div>
      <div class="pagination">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="size"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="load"
          @size-change="load"
        />
      </div>
    </div>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑证书监控' : '添加证书监控'" width="540px" destroy-on-close append-to-body>
      <el-form ref="formRef" :model="form" :rules="formRules" label-position="top">
        <el-form-item label="监控域名" prop="domain">
          <el-input v-model="form.domain" placeholder="example.com" :disabled="!!editing" />
          <div class="form-hint">可监控任意公网 HTTPS 端点，系统会拒绝内网与保留地址访问。</div>
        </el-form-item>
        <div class="two-col">
          <el-form-item label="HTTPS 端口">
            <el-input-number v-model="form.port" :min="1" :max="65535" controls-position="right" style="width: 100%" />
          </el-form-item>
          <el-form-item label="自定义 SNI">
            <el-input v-model="form.sni" placeholder="默认使用监控域名" />
          </el-form-item>
        </div>
        <el-form-item label="监控与校验选项">
          <div class="option-stack">
            <div class="switch-row"><el-switch v-model="form.monitor_enabled" /><span>启用定时检测</span></div>
            <div class="switch-row"><el-switch v-model="form.skip_verify" /><span>跳过证书链校验（仅诊断，不推荐）</span></div>
            <div v-if="editing?.managed" class="switch-row"><el-switch v-model="form.auto_renew" /><span>证书到期前自动续期</span></div>
          </div>
        </el-form-item>
        <el-alert
          v-if="form.skip_verify"
          title="跳过校验仅用于证书诊断，不会作为默认安全策略。生产环境应保持关闭。"
          type="warning"
          :closable="false"
          show-icon
        />
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="detailVisible" title="SSL 证书详情" width="720px" append-to-body>
      <el-descriptions v-if="detailCert" :column="2" border size="small">
        <el-descriptions-item label="监控端点" :span="2">
          <span class="mono">{{ detailCert.domain }}:{{ detailCert.port }}</span>
          <el-tag v-if="detailCert.managed" type="success" size="small" effect="plain" style="margin-left: 8px">ACME 托管</el-tag>
          <el-tag v-if="detailCert.skip_verify" type="warning" size="small" effect="plain" style="margin-left: 6px">跳过校验</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="HTTPS 状态">{{ httpsStatus[detailCert.https_status] || detailCert.https_status }}</el-descriptions-item>
        <el-descriptions-item label="证书状态">{{ certStatus[detailCert.status]?.label || detailCert.status }}</el-descriptions-item>
        <el-descriptions-item label="颁发机构">{{ detailCert.issuer || '—' }}</el-descriptions-item>
        <el-descriptions-item label="证书主题">{{ detailCert.subject || '—' }}</el-descriptions-item>
        <el-descriptions-item label="生效时间">{{ formatDate(detailCert.not_before) }}</el-descriptions-item>
        <el-descriptions-item label="到期时间">{{ formatDate(detailCert.not_after) }}（{{ daysText(detailCert.days_remaining) }}）</el-descriptions-item>
        <el-descriptions-item label="证书链">{{ detailCert.chain_valid ? '有效' : '无效或不受信任' }}</el-descriptions-item>
        <el-descriptions-item label="域名匹配">{{ detailCert.hostname_valid ? '匹配' : '不匹配' }}</el-descriptions-item>
        <el-descriptions-item label="序列号" :span="2"><span class="mono">{{ detailCert.serial_number || '—' }}</span></el-descriptions-item>
        <el-descriptions-item label="SAN 域名" :span="2">
          <div class="san-list">
            <el-tag v-for="name in detailCert.san" :key="name" size="small" effect="plain">{{ name }}</el-tag>
            <span v-if="!detailCert.san.length" class="muted">—</span>
          </div>
        </el-descriptions-item>
        <el-descriptions-item label="最后检测" :span="2">{{ formatDateTime(detailCert.last_checked_at) }}</el-descriptions-item>
        <el-descriptions-item v-if="detailCert.last_error" label="错误信息" :span="2">
          <span style="color: var(--dm-danger)">{{ detailCert.last_error }}</span>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import type { FormInstance, FormRules } from 'element-plus'
import {
  Aim, ArrowDown, CircleCheckFilled, Delete, DocumentAdd, Download, Edit, Key, Lock, Plus, Refresh, Search, Upload, View, WarningFilled,
} from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { Certificate, Page } from '@/api/types'
import {
  certStatus, daysClass, daysText, downloadBlob, formatDate, formatDateTime, httpsStatus,
} from '@/utils/status'

const router = useRouter()
const route = useRoute()
const loading = ref(false)
const items = ref<Certificate[]>([])
const total = ref(0)
const page = ref(1)
const size = ref(20)
const filters = reactive({
  search: '',
  status: typeof route.query.status === 'string' ? route.query.status : '',
  managed: typeof route.query.managed === 'string' ? route.query.managed : '',
})
const rowChecking = ref<number | null>(null)
const checkingAll = ref(false)

const detailVisible = ref(false)
const detailCert = ref<Certificate | null>(null)
const dialogVisible = ref(false)
const editing = ref<Certificate | null>(null)
const saving = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({ domain: '', port: 443, sni: '', skip_verify: false, monitor_enabled: true, auto_renew: false })
const formRules: FormRules = {
  domain: [
    { required: true, message: '请输入域名', trigger: 'blur' },
    { pattern: /^(?!-)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, message: '域名格式无效', trigger: 'blur' },
  ],
}

async function load() {
  loading.value = true
  try {
    const data = await api.get<Page<Certificate>>('/certificates', {
      page: page.value, page_size: size.value,
      search: filters.search || undefined, status: filters.status || undefined,
      managed: filters.managed || undefined,
    })
    items.value = data.items
    total.value = data.total
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

function applySearch() {
  page.value = 1
  load()
}

function openCreate() {
  editing.value = null
  Object.assign(form, { domain: '', port: 443, sni: '', skip_verify: false, monitor_enabled: true, auto_renew: false })
  dialogVisible.value = true
}

function openEdit(row: Certificate) {
  editing.value = row
  Object.assign(form, {
    domain: row.domain, port: row.port, sni: row.sni || '',
    skip_verify: row.skip_verify, monitor_enabled: row.monitor_enabled, auto_renew: row.auto_renew,
  })
  dialogVisible.value = true
}

async function save() {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  saving.value = true
  try {
    if (editing.value) {
      await api.put(`/certificates/${editing.value.id}`, {
        port: form.port, sni: form.sni, skip_verify: form.skip_verify,
        monitor_enabled: form.monitor_enabled,
        auto_renew: editing.value.managed ? form.auto_renew : undefined,
      })
      ElMessage.success('证书监控已更新')
    } else {
      await api.post('/certificates', {
        domain: form.domain.trim(), port: form.port, sni: form.sni,
        skip_verify: form.skip_verify, monitor_enabled: form.monitor_enabled,
      })
      ElMessage.success('证书监控已添加')
    }
    dialogVisible.value = false
    load()
  } catch (error) {
    showError(error)
  } finally {
    saving.value = false
  }
}

async function checkOne(row: Certificate) {
  rowChecking.value = row.id
  try {
    const updated = await api.post<Certificate>(`/certificates/${row.id}/check`)
    Object.assign(row, updated)
    ElMessage.success(`检测完成：${certStatus[updated.status]?.label || updated.status}`)
    load()
  } catch (error) {
    showError(error)
  } finally {
    rowChecking.value = null
  }
}

async function checkAll() {
  try {
    await ElMessageBox.confirm('将异步检测所有已启用的 HTTPS 端点，是否继续？', '检测全部证书', {
      confirmButtonText: '开始检测', cancelButtonText: '取消', type: 'info',
    })
  } catch {
    return
  }
  checkingAll.value = true
  try {
    await api.post('/certificates/check', { all: true })
    ElMessage.success('已开始后台检测，请稍后刷新查看')
    setTimeout(load, 4000)
  } catch (error) {
    showError(error)
  } finally {
    checkingAll.value = false
  }
}

async function renew(row: Certificate) {
  try {
    await ElMessageBox.confirm(`确定为 ${row.domain} 创建 ACME 续期订单吗？将复用原订单的验证方式与 DNS 配置。`, '手动续期', {
      confirmButtonText: '创建续期订单', cancelButtonText: '取消', type: 'info',
    })
  } catch {
    return
  }
  try {
    await api.post(`/certificates/${row.id}/renew`)
    ElMessage.success('续期订单已创建，可在证书申请页查看进度')
    router.push('/apply')
  } catch (error) {
    showError(error)
  }
}

async function toggleAutoRenew(row: Certificate, value: boolean) {
  try {
    await api.put(`/certificates/${row.id}`, { auto_renew: value })
    row.auto_renew = value
    ElMessage.success(value ? '已开启自动续期' : '已关闭自动续期')
  } catch (error) {
    showError(error)
  }
}

async function download(row: Certificate, kind: string) {
  if (kind === 'privkey') {
    try {
      await ElMessageBox.confirm(
        '私钥是 HTTPS 服务的核心凭据，请确保下载链路与保存位置安全。系统不会在页面中显示私钥。继续下载吗？',
        '下载私钥文件',
        { confirmButtonText: '确认下载', cancelButtonText: '取消', type: 'warning' },
      )
    } catch {
      return
    }
  }
  try {
    const blob = await api.blob(`/certificates/${row.id}/download`, { type: kind, confirm: kind === 'privkey' ? 1 : undefined })
    const name = kind === 'privkey' ? 'privkey.pem' : kind === 'cert' ? 'cert.pem' : kind === 'chain' ? 'chain.pem' : 'fullchain.pem'
    downloadBlob(blob, `${row.domain.replace(/\*/g, 'wildcard')}-${name}`)
  } catch (error) {
    showError(error)
  }
}

async function deploy(row: Certificate) {
  try {
    await ElMessageBox.confirm('将证书文件写入系统设置中的部署目录，并执行已配置的部署脚本（如有）。是否继续？', '部署证书', {
      confirmButtonText: '开始部署', cancelButtonText: '取消', type: 'info',
    })
  } catch {
    return
  }
  try {
    const result = await api.post<{ directory: string }>(`/certificates/${row.id}/deploy`)
    ElMessage.success(`证书已部署到 ${result.directory}`)
  } catch (error) {
    showError(error)
  }
}

async function remove(row: Certificate) {
  try {
    await ElMessageBox.confirm(`确定删除 ${row.domain}:${row.port} 的证书监控吗？托管证书的本地文件也会被删除。`, '删除证书监控', {
      confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning',
    })
  } catch {
    return
  }
  try {
    await api.delete(`/certificates/${row.id}`)
    ElMessage.success('已删除')
    if (items.value.length === 1 && page.value > 1) page.value--
    load()
  } catch (error) {
    showError(error)
  }
}

function handleCommand(command: string, row: Certificate) {
  switch (command) {
    case 'detail': detailCert.value = row; detailVisible.value = true; break
    case 'download-fullchain': download(row, 'fullchain'); break
    case 'download-cert': download(row, 'cert'); break
    case 'download-privkey': download(row, 'privkey'); break
    case 'deploy': deploy(row); break
    case 'apply': router.push({ path: '/apply', query: { domain: row.domain.replace(/^\*\./, '') } }); break
    case 'edit': openEdit(row); break
    case 'delete': remove(row); break
  }
}

onMounted(load)
</script>

<style scoped>
.endpoint-cell {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.endpoint-avatar {
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  display: grid;
  place-items: center;
  border-radius: 9px;
  background: rgba(14, 165, 233, 0.1);
  color: #0ea5e9;
}
.endpoint-avatar.managed {
  background: var(--dm-primary-soft);
  color: var(--dm-primary);
}
.endpoint-info {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.endpoint-name {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.endpoint-meta {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10.5px;
  color: var(--dm-text-muted);
  white-space: nowrap;
  overflow: hidden;
}
.error-icon {
  color: var(--dm-danger);
  font-size: 14px;
  flex: 0 0 auto;
}
.issuer-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.verify-badges {
  display: flex;
  align-items: center;
  gap: 5px;
}
.verify-badges .el-icon {
  font-size: 13px;
}
.verify-badges .el-icon.ok { color: #10b981; }
.verify-badges .el-icon.bad { color: #ef4444; }
.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.san-list {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.option-stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.switch-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: var(--dm-text-secondary);
}
:deep(.error-tooltip) {
  max-width: 380px;
  line-height: 1.6;
}
@media (max-width: 560px) {
  .two-col { grid-template-columns: 1fr; }
}
</style>
