<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">监控日志</h1>
        <p class="page-subtitle">查看域名检测、SSL 检测与告警通知的完整执行记录。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <div class="panel">
      <el-tabs v-model="activeTab" class="log-tabs" @tab-change="onTabChange">
        <el-tab-pane label="监控检测日志" name="monitor">
          <div class="toolbar inner-toolbar">
            <div class="toolbar-left">
              <el-select v-model="monitorFilters.kind" placeholder="类型" clearable style="width: 120px" @change="searchMonitor">
                <el-option label="域名" value="domain" />
                <el-option label="SSL" value="ssl" />
                <el-option label="证书" value="certificate" />
                <el-option label="ACME" value="acme" />
                <el-option label="系统" value="system" />
              </el-select>
              <el-select v-model="monitorFilters.status" placeholder="状态" clearable style="width: 120px" @change="searchMonitor">
                <el-option label="成功" value="success" />
                <el-option label="失败" value="failed" />
                <el-option label="信息" value="info" />
              </el-select>
              <el-input v-model="monitorFilters.target" placeholder="搜索检测目标" clearable style="width: 200px" @keyup.enter="searchMonitor" @clear="searchMonitor" />
              <el-date-picker
                v-model="monitorFilters.range"
                type="daterange"
                value-format="YYYY-MM-DD"
                range-separator="至"
                start-placeholder="开始日期"
                end-placeholder="结束日期"
                style="width: 250px"
                @change="searchMonitor"
              />
              <el-button :icon="Search" @click="searchMonitor">查询</el-button>
            </div>
          </div>
          <div class="table-wrap">
            <el-table v-loading="loading" :data="monitorItems" class="dm-table" empty-text="暂无检测日志">
              <el-table-column label="时间" width="168">
                <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
              </el-table-column>
              <el-table-column label="类型" width="95">
                <template #default="{ row }">
                  <el-tag size="small" effect="plain" :type="kindType(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="target" label="检测目标" min-width="190">
                <template #default="{ row }"><span class="mono target-text">{{ row.target }}</span></template>
              </el-table-column>
              <el-table-column prop="action" label="动作" width="105">
                <template #default="{ row }">{{ actionLabel(row.action) }}</template>
              </el-table-column>
              <el-table-column label="状态" width="90">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.status === 'success' ? 'success' : row.status === 'failed' ? 'danger' : 'info'" effect="light">
                    {{ row.status === 'success' ? '成功' : row.status === 'failed' ? '失败' : '信息' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="耗时" width="90" align="right">
                <template #default="{ row }">{{ formatDuration(row.duration_ms) }}</template>
              </el-table-column>
              <el-table-column label="结果信息" min-width="260">
                <template #default="{ row }">
                  <span class="log-message" :class="{ danger: row.status === 'failed' }">{{ row.message || '—' }}</span>
                </template>
              </el-table-column>
              <el-table-column label="操作" width="80" fixed="right">
                <template #default="{ row }">
                  <el-button link type="primary" @click="showMonitorDetail(row)">详情</el-button>
                </template>
              </el-table-column>
            </el-table>
          </div>
          <div class="pagination">
            <el-pagination
              v-model:current-page="monitorPage"
              v-model:page-size="monitorSize"
              :total="monitorTotal"
              :page-sizes="[20, 50, 100]"
              layout="total, sizes, prev, pager, next"
              @current-change="loadMonitor"
              @size-change="loadMonitor"
            />
          </div>
        </el-tab-pane>

        <el-tab-pane label="通知发送日志" name="notification">
          <div class="toolbar inner-toolbar">
            <div class="toolbar-left">
              <el-select v-model="notificationFilters.event" placeholder="事件" clearable style="width: 175px" @change="searchNotification">
                <el-option v-for="(label, key) in eventTypes" :key="key" :label="label" :value="key" />
              </el-select>
              <el-select v-model="notificationFilters.status" placeholder="状态" clearable style="width: 120px" @change="searchNotification">
                <el-option label="已发送" value="success" />
                <el-option label="发送失败" value="failed" />
                <el-option label="发送中" value="pending" />
              </el-select>
              <el-input v-model="notificationFilters.channel" placeholder="渠道名称" clearable style="width: 160px" @keyup.enter="searchNotification" @clear="searchNotification" />
              <el-input v-model="notificationFilters.subject" placeholder="告警对象" clearable style="width: 180px" @keyup.enter="searchNotification" @clear="searchNotification" />
              <el-button :icon="Search" @click="searchNotification">查询</el-button>
            </div>
          </div>
          <div class="table-wrap">
            <el-table v-loading="loading" :data="notificationItems" class="dm-table" empty-text="暂无通知日志">
              <el-table-column label="时间" width="168">
                <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
              </el-table-column>
              <el-table-column label="事件" width="155">
                <template #default="{ row }">{{ eventTypes[row.event] || row.event }}</template>
              </el-table-column>
              <el-table-column prop="subject" label="告警对象" min-width="160">
                <template #default="{ row }"><span class="mono">{{ row.subject }}</span></template>
              </el-table-column>
              <el-table-column prop="channel_name" label="通知渠道" width="145" />
              <el-table-column label="状态" width="105">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.status === 'success' ? 'success' : row.status === 'failed' ? 'danger' : 'info'" effect="light">
                    {{ row.status === 'success' ? '已发送' : row.status === 'failed' ? '失败' : '发送中' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="尝试" width="70" align="center">
                <template #default="{ row }">{{ row.attempts }}</template>
              </el-table-column>
              <el-table-column label="标题" min-width="220">
                <template #default="{ row }">{{ row.title }}</template>
              </el-table-column>
              <el-table-column label="操作" width="80" fixed="right">
                <template #default="{ row }">
                  <el-button link type="primary" @click="showNotificationDetail(row)">详情</el-button>
                </template>
              </el-table-column>
            </el-table>
          </div>
          <div class="pagination">
            <el-pagination
              v-model:current-page="notificationPage"
              v-model:page-size="notificationSize"
              :total="notificationTotal"
              :page-sizes="[20, 50, 100]"
              layout="total, sizes, prev, pager, next"
              @current-change="loadNotification"
              @size-change="loadNotification"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>

    <el-dialog v-model="monitorDetailVisible" title="检测日志详情" width="620px" append-to-body>
      <el-descriptions v-if="activeMonitor" :column="2" size="small" border>
        <el-descriptions-item label="时间">{{ formatDateTime(activeMonitor.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="类型">{{ kindLabel(activeMonitor.kind) }}</el-descriptions-item>
        <el-descriptions-item label="目标">{{ activeMonitor.target }}</el-descriptions-item>
        <el-descriptions-item label="动作">{{ actionLabel(activeMonitor.action) }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ activeMonitor.status }}</el-descriptions-item>
        <el-descriptions-item label="耗时">{{ formatDuration(activeMonitor.duration_ms) }}</el-descriptions-item>
        <el-descriptions-item label="结果" :span="2">{{ activeMonitor.message || '—' }}</el-descriptions-item>
        <el-descriptions-item label="详情" :span="2">
          <pre class="detail-pre">{{ prettyDetails(activeMonitor.details) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <el-dialog v-model="notificationDetailVisible" title="通知发送详情" width="640px" append-to-body>
      <el-descriptions v-if="activeNotification" :column="2" size="small" border>
        <el-descriptions-item label="事件">{{ eventTypes[activeNotification.event] || activeNotification.event }}</el-descriptions-item>
        <el-descriptions-item label="对象">{{ activeNotification.subject }}</el-descriptions-item>
        <el-descriptions-item label="渠道">{{ activeNotification.channel_name }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ activeNotification.status }}</el-descriptions-item>
        <el-descriptions-item label="尝试次数">{{ activeNotification.attempts }}</el-descriptions-item>
        <el-descriptions-item label="发送时间">{{ formatDateTime(activeNotification.sent_at) }}</el-descriptions-item>
        <el-descriptions-item label="错误" :span="2">{{ activeNotification.error || '—' }}</el-descriptions-item>
        <el-descriptions-item label="消息内容" :span="2">
          <pre class="detail-pre">{{ activeNotification.title }}\n\n{{ activeNotification.content }}</pre>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Refresh, Search } from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { MonitorLog, NotificationLog, Page } from '@/api/types'
import { eventTypes, formatDateTime, formatDuration } from '@/utils/status'

const route = useRoute()
const activeTab = ref(route.query.tab === 'notification' ? 'notification' : 'monitor')
const loading = ref(false)

const monitorFilters = reactive({ kind: '', status: '', target: '', range: [] as string[] })
const monitorItems = ref<MonitorLog[]>([])
const monitorTotal = ref(0)
const monitorPage = ref(1)
const monitorSize = ref(20)
const monitorDetailVisible = ref(false)
const activeMonitor = ref<MonitorLog | null>(null)

const notificationFilters = reactive({ event: '', status: '', channel: '', subject: '' })
const notificationItems = ref<NotificationLog[]>([])
const notificationTotal = ref(0)
const notificationPage = ref(1)
const notificationSize = ref(20)
const notificationDetailVisible = ref(false)
const activeNotification = ref<NotificationLog | null>(null)

function kindLabel(kind: string) {
  return { domain: '域名', ssl: 'SSL', certificate: '证书', acme: 'ACME', system: '系统' }[kind] || kind
}
function kindType(kind: string) {
  if (kind === 'domain') return 'primary'
  if (kind === 'ssl') return 'success'
  if (kind === 'certificate') return 'warning'
  if (kind === 'system') return 'danger'
  return 'info'
}
function actionLabel(action: string) {
  return {
    auto: '自动', scheduled: '定时', manual: '手动', import: '导入', download: '下载', deploy: '部署',
  }[action] || action || '—'
}

async function loadMonitor() {
  loading.value = true
  try {
    const data = await api.get<Page<MonitorLog>>('/logs/monitor', {
      page: monitorPage.value, page_size: monitorSize.value,
      kind: monitorFilters.kind || undefined, status: monitorFilters.status || undefined,
      target: monitorFilters.target || undefined,
      start: monitorFilters.range?.[0] || undefined, end: monitorFilters.range?.[1] || undefined,
    })
    monitorItems.value = data.items
    monitorTotal.value = data.total
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

async function loadNotification() {
  loading.value = true
  try {
    const data = await api.get<Page<NotificationLog>>('/logs/notification', {
      page: notificationPage.value, page_size: notificationSize.value,
      event: notificationFilters.event || undefined, status: notificationFilters.status || undefined,
      channel: notificationFilters.channel || undefined, subject: notificationFilters.subject || undefined,
    })
    notificationItems.value = data.items
    notificationTotal.value = data.total
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

function load() {
  if (activeTab.value === 'monitor') loadMonitor()
  else loadNotification()
}
function searchMonitor() { monitorPage.value = 1; loadMonitor() }
function searchNotification() { notificationPage.value = 1; loadNotification() }
function onTabChange() { load() }

function showMonitorDetail(row: MonitorLog) {
  activeMonitor.value = row
  monitorDetailVisible.value = true
}
function showNotificationDetail(row: NotificationLog) {
  activeNotification.value = row
  notificationDetailVisible.value = true
}
function prettyDetails(raw: string) {
  if (!raw) return '—'
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

onMounted(load)
</script>

<style scoped>
.log-tabs {
  padding-top: 4px;
}
.log-tabs :deep(.el-tabs__header) {
  margin: 0;
  padding: 0 20px;
}
.log-tabs :deep(.el-tabs__item) {
  font-weight: 600;
}
.inner-toolbar {
  border-top: 1px solid var(--dm-border);
}
.target-text {
  display: block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.log-message {
  display: block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--dm-text-secondary);
  font-size: 12px;
}
.log-message.danger {
  color: var(--dm-danger);
}
.detail-pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.65;
  max-height: 300px;
  overflow: auto;
}
</style>
