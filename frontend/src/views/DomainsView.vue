<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">域名管理</h1>
        <p class="page-subtitle">通过 RDAP / WHOIS 监控域名注册商与到期时间，查询失败不会被视为域名过期。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="Download" @click="downloadTemplate">CSV 模板</el-button>
        <el-button :icon="Upload" @click="openImport">批量导入</el-button>
        <el-button type="primary" :icon="Plus" @click="openCreate">添加域名</el-button>
      </div>
    </div>

    <div class="panel">
      <div class="toolbar">
        <div class="toolbar-left">
          <el-input
            v-model="filters.search"
            placeholder="搜索域名、注册商或备注"
            clearable
            style="width: 260px"
            :prefix-icon="Search"
            @keyup.enter="applySearch"
            @clear="applySearch"
          />
          <el-select v-model="filters.status" placeholder="全部状态" clearable style="width: 150px" @change="applySearch">
            <el-option v-for="(item, key) in domainStatus" :key="key" :label="item.label" :value="key" />
          </el-select>
          <el-button :icon="Search" @click="applySearch">查询</el-button>
        </div>
        <div class="toolbar-right">
          <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
          <el-button :icon="Aim" :loading="checkingAll" @click="checkAll">检测全部</el-button>
        </div>
      </div>

      <div class="table-wrap">
        <el-table v-loading="loading" :data="items" class="dm-table" row-key="id" empty-text="暂无域名，点击右上角添加">
          <el-table-column label="域名" min-width="200" fixed="left">
            <template #default="{ row }">
              <div class="domain-cell">
                <div class="domain-avatar">D</div>
                <div class="domain-info">
                  <span class="domain-name">{{ row.name }}</span>
                  <span class="domain-note">{{ row.notes || '未填写备注' }}</span>
                </div>
                <el-tooltip v-if="row.last_error" :content="row.last_error" placement="top" popper-class="error-tooltip">
                  <el-icon class="error-icon"><WarningFilled /></el-icon>
                </el-tooltip>
              </div>
            </template>
          </el-table-column>
          <el-table-column prop="registrar" label="注册商" min-width="150">
            <template #default="{ row }">{{ row.registrar || '—' }}</template>
          </el-table-column>
          <el-table-column label="注册时间" width="120">
            <template #default="{ row }">{{ formatDate(row.registered_at) }}</template>
          </el-table-column>
          <el-table-column label="到期时间" width="135">
            <template #default="{ row }">
              <div class="expire-cell">
                <span>{{ formatDate(row.expires_at) }}</span>
                <el-tag v-if="row.expiry_source === 'manual'" size="small" type="info" effect="plain">手动</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="剩余天数" width="130">
            <template #default="{ row }">
              <div v-if="row.expires_at" class="days-cell">
                <span :class="daysClass(row.days_remaining)">{{ daysText(row.days_remaining) }}</span>
                <el-progress
                  :percentage="progress(row.days_remaining)"
                  :stroke-width="4"
                  :show-text="false"
                  :color="progressColor(row.days_remaining)"
                />
              </div>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column label="域名状态" width="115">
            <template #default="{ row }">
              <el-tag :type="domainStatus[row.status]?.type || 'info'" effect="light">
                {{ domainStatus[row.status]?.label || row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="监控" width="80" align="center">
            <template #default="{ row }">
              <el-switch
                :model-value="row.monitor_enabled"
                size="small"
                @change="(value: boolean) => toggleMonitor(row, value)"
              />
            </template>
          </el-table-column>
          <el-table-column label="最后检测" width="165">
            <template #default="{ row }">{{ formatDateTime(row.last_checked_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="190" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" :loading="rowChecking === row.id" @click="checkOne(row)">检测</el-button>
              <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
              <el-button link type="danger" @click="remove(row)">删除</el-button>
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

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑域名' : '添加域名'" width="520px" destroy-on-close append-to-body>
      <el-form ref="formRef" :model="form" :rules="formRules" label-position="top">
        <el-form-item label="域名" prop="name">
          <el-input v-model="form.name" placeholder="example.com" :disabled="!!editing" />
          <div class="form-hint">仅填写域名，无需包含 https:// 或路径。查询失败时可手动锁定到期时间。</div>
        </el-form-item>
        <el-form-item label="监控状态">
          <div class="switch-row">
            <el-switch v-model="form.monitor_enabled" />
            <span>{{ form.monitor_enabled ? '启用自动检测与告警扫描' : '暂停自动检测与告警扫描' }}</span>
          </div>
        </el-form-item>
        <el-form-item label="手动锁定到期时间">
          <div class="switch-row" style="margin-bottom: 10px">
            <el-switch v-model="form.expiry_locked" />
            <span>适用于 RDAP/WHOIS 无法查询到到期时间的域名</span>
          </div>
          <el-date-picker
            v-if="form.expiry_locked"
            v-model="form.expires_at"
            type="date"
            value-format="YYYY-MM-DD"
            placeholder="选择到期日期"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.notes" type="textarea" :rows="3" maxlength="2000" show-word-limit placeholder="可选，例如：客户官网、负责人等" />
        </el-form-item>
        <el-form-item v-if="!editing" label="创建后立即检测">
          <el-switch v-model="form.auto_check" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="importVisible" title="批量导入域名" width="620px" destroy-on-close append-to-body>
      <div class="alert-box" style="margin-bottom: 16px">
        支持 CSV / TXT，单次最多 1000 条、最大 2MB。CSV 第一列域名，第二列到期日期（可选），第三列备注（可选）。
        首行表头可为 <code>domain,expires_at,notes</code>。
      </div>
      <el-upload
        drag
        :auto-upload="false"
        :limit="1"
        accept=".csv,.txt"
        :on-change="onFileChange"
        :on-remove="() => (importFile = null)"
        :file-list="fileList"
      >
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">拖拽 CSV / TXT 文件到此处，或 <em>点击选择</em></div>
      </el-upload>
      <el-divider>或直接粘贴</el-divider>
      <el-input v-model="importText" type="textarea" :rows="5" placeholder="example.com,2027-12-01,备注&#10;www.example.com" />
      <div class="switch-row" style="margin-top: 14px">
        <el-switch v-model="importAutoCheck" />
        <span>导入后自动检测域名信息</span>
      </div>
      <el-alert
        v-if="importResult"
        class="import-result"
        :type="importResult.invalid > 0 ? 'warning' : 'success'"
        :closable="false"
        show-icon
      >
        <template #title>
          导入完成：成功 {{ importResult.imported }}，跳过 {{ importResult.skipped }}，无效 {{ importResult.invalid }}
        </template>
        <div v-if="importResult.errors?.length" class="import-errors">
          <div v-for="(err, index) in importResult.errors" :key="index">{{ err }}</div>
        </div>
      </el-alert>
      <template #footer>
        <el-button @click="importVisible = false">关闭</el-button>
        <el-button type="primary" :loading="importing" @click="runImport">开始导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import type { FormInstance, FormRules, UploadFile, UploadFiles } from 'element-plus'
import {
  Aim, Download, Plus, Refresh, Search, Upload, UploadFilled, WarningFilled,
} from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { Domain, Page } from '@/api/types'
import {
  daysClass, daysText, domainStatus, downloadBlob, formatDate, formatDateTime, parseCSVTemplate,
} from '@/utils/status'

interface ImportResult {
  imported: number
  skipped: number
  invalid: number
  errors: string[]
}

const loading = ref(false)
const items = ref<Domain[]>([])
const total = ref(0)
const page = ref(1)
const size = ref(20)
const filters = reactive({ search: '', status: '' })
const rowChecking = ref<number | null>(null)
const checkingAll = ref(false)

const dialogVisible = ref(false)
const editing = ref<Domain | null>(null)
const saving = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({
  name: '', notes: '', expiry_locked: false, expires_at: '', monitor_enabled: true, auto_check: true,
})
const formRules: FormRules = {
  name: [
    { required: true, message: '请输入域名', trigger: 'blur' },
    { pattern: /^(?!-)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, message: '域名格式无效', trigger: 'blur' },
  ],
}

const importVisible = ref(false)
const importing = ref(false)
const importFile = ref<File | null>(null)
const fileList = ref<UploadFile[]>([])
const importText = ref('')
const importAutoCheck = ref(true)
const importResult = ref<ImportResult | null>(null)

async function load() {
  loading.value = true
  try {
    const data = await api.get<Page<Domain>>('/domains', {
      page: page.value, page_size: size.value,
      search: filters.search || undefined, status: filters.status || undefined,
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
  Object.assign(form, { name: '', notes: '', expiry_locked: false, expires_at: '', monitor_enabled: true, auto_check: true })
  dialogVisible.value = true
}

function openEdit(row: Domain) {
  editing.value = row
  Object.assign(form, {
    name: row.name,
    notes: row.notes || '',
    expiry_locked: row.expiry_locked,
    expires_at: row.expires_at ? row.expires_at.slice(0, 10) : '',
    monitor_enabled: row.monitor_enabled,
    auto_check: false,
  })
  dialogVisible.value = true
}

async function save() {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  if (form.expiry_locked && !form.expires_at) {
    ElMessage.warning('请选择手动锁定的到期日期')
    return
  }
  saving.value = true
  try {
    if (editing.value) {
      const payload: Record<string, unknown> = {
        notes: form.notes,
        monitor_enabled: form.monitor_enabled,
      }
      if (form.expiry_locked) {
        payload.expires_at = form.expires_at
        payload.expiry_locked = true
      } else {
        payload.expiry_locked = false
      }
      await api.put(`/domains/${editing.value.id}`, payload)
      ElMessage.success('域名已更新')
    } else {
      await api.post('/domains', {
        name: form.name.trim(),
        notes: form.notes,
        expires_at: form.expiry_locked ? form.expires_at : '',
        monitor_enabled: form.monitor_enabled,
        auto_check: form.auto_check,
      })
      ElMessage.success('域名已添加')
    }
    dialogVisible.value = false
    load()
  } catch (error) {
    showError(error)
  } finally {
    saving.value = false
  }
}

async function toggleMonitor(row: Domain, value: boolean) {
  try {
    await api.put(`/domains/${row.id}`, { monitor_enabled: value })
    row.monitor_enabled = value
    ElMessage.success(value ? '已启用监控' : '已暂停监控')
  } catch (error) {
    showError(error)
  }
}

async function checkOne(row: Domain) {
  rowChecking.value = row.id
  try {
    const updated = await api.post<Domain>(`/domains/${row.id}/check`)
    Object.assign(row, updated)
    ElMessage.success(updated.last_error ? '检测完成，但查询失败，请查看提示' : '域名检测完成')
    load()
  } catch (error) {
    showError(error)
  } finally {
    rowChecking.value = null
  }
}

async function checkAll() {
  try {
    await ElMessageBox.confirm('将异步检测所有已启用监控的域名，可能耗时较长。是否继续？', '检测全部域名', {
      confirmButtonText: '开始检测', cancelButtonText: '取消', type: 'info',
    })
  } catch {
    return
  }
  checkingAll.value = true
  try {
    await api.post('/domains/check-all')
    ElMessage.success('已开始后台检测，请稍后刷新查看结果')
    setTimeout(load, 4000)
  } catch (error) {
    showError(error)
  } finally {
    checkingAll.value = false
  }
}

async function remove(row: Domain) {
  try {
    await ElMessageBox.confirm(`确定删除域名 ${row.name} 吗？相关非托管 SSL 监控记录也会被删除。`, '删除域名', {
      confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning',
    })
  } catch {
    return
  }
  try {
    await api.delete(`/domains/${row.id}`)
    ElMessage.success('域名已删除')
    if (items.value.length === 1 && page.value > 1) page.value--
    load()
  } catch (error) {
    showError(error)
  }
}

function progress(days: number) {
  if (days < 0) return 0
  return Math.min(100, Math.round((Math.min(days, 365) / 365) * 100))
}
function progressColor(days: number) {
  if (days < 0) return '#ef4444'
  if (days <= 7) return '#ef4444'
  if (days <= 30) return '#f59e0b'
  return '#10b981'
}

function openImport() {
  importFile.value = null
  fileList.value = []
  importText.value = ''
  importAutoCheck.value = true
  importResult.value = null
  importVisible.value = true
}

function onFileChange(file: UploadFile, files: UploadFiles) {
  importFile.value = file.raw || null
  fileList.value = files.slice(-1)
}

async function runImport() {
  if (!importFile.value && !importText.value.trim()) {
    ElMessage.warning('请选择文件或粘贴域名列表')
    return
  }
  importing.value = true
  importResult.value = null
  try {
    const formData = new FormData()
    if (importFile.value) formData.append('file', importFile.value)
    else formData.append('text', importText.value)
    formData.append('auto_check', String(importAutoCheck.value))
    importResult.value = await api.upload<ImportResult>('/domains/import', formData)
    if (importResult.value.imported > 0) {
      ElMessage.success(`成功导入 ${importResult.value.imported} 个域名`)
      load()
    }
  } catch (error) {
    showError(error)
  } finally {
    importing.value = false
  }
}

function downloadTemplate() {
  downloadBlob(new Blob([parseCSVTemplate()], { type: 'text/csv;charset=utf-8' }), 'domain-import-template.csv')
}

onMounted(load)
</script>

<style scoped>
.domain-cell {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.domain-avatar {
  width: 32px;
  height: 32px;
  border-radius: 9px;
  display: grid;
  place-items: center;
  flex: 0 0 32px;
  background: linear-gradient(135deg, rgba(15, 157, 138, 0.14), rgba(14, 165, 233, 0.12));
  color: var(--dm-primary);
  font-size: 12px;
  font-weight: 750;
}
.domain-info {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.domain-name {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.domain-note {
  color: var(--dm-text-muted);
  font-size: 10.5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 150px;
}
.error-icon {
  color: var(--dm-danger);
  font-size: 14px;
  flex: 0 0 auto;
}
.expire-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}
.days-cell {
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.switch-row {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--dm-text-secondary);
  font-size: 12px;
}
.import-result {
  margin-top: 16px;
}
.import-errors {
  max-height: 100px;
  overflow: auto;
  margin-top: 6px;
  font-size: 12px;
  line-height: 1.7;
}
:deep(.error-tooltip) {
  max-width: 380px;
  line-height: 1.6;
}
</style>
