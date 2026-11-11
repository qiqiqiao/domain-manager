<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">仪表盘</h1>
        <p class="page-subtitle">域名与 SSL 证书运行概览，数据实时汇总自监控任务。</p>
      </div>
      <div class="page-actions">
        <span class="update-hint">更新于 {{ updatedAt }}</span>
        <el-button :icon="Refresh" :loading="loading" @click="load">刷新数据</el-button>
      </div>
    </div>

    <section class="stat-grid">
      <div class="stat-card" v-for="item in domainCards" :key="item.label">
        <div class="stat-label"><span class="dot" :style="{ background: item.color }"></span>{{ item.label }}</div>
        <div class="stat-value">{{ item.value }}</div>
        <div class="stat-foot">{{ item.foot }}</div>
        <div class="stat-icon"><el-icon><component :is="item.icon" /></el-icon></div>
      </div>
    </section>

    <section class="stat-grid section-gap">
      <div class="stat-card" v-for="item in sslCards" :key="item.label">
        <div class="stat-label"><span class="dot" :style="{ background: item.color }"></span>{{ item.label }}</div>
        <div class="stat-value">{{ item.value }}</div>
        <div class="stat-foot">{{ item.foot }}</div>
        <div class="stat-icon"><el-icon><component :is="item.icon" /></el-icon></div>
      </div>
    </section>

    <section class="activity-grid section-gap">
      <div class="activity-card panel">
        <div class="activity-icon danger"><el-icon><WarningFilled /></el-icon></div>
        <div>
          <span>HTTPS 异常</span>
          <strong>{{ counts.https_abnormal || 0 }}</strong>
        </div>
        <el-button link type="primary" @click="router.push('/certificates')">查看</el-button>
      </div>
      <div class="activity-card panel">
        <div class="activity-icon teal"><el-icon><DataLine /></el-icon></div>
        <div>
          <span>今日检测次数</span>
          <strong>{{ counts.today_checks || 0 }}</strong>
        </div>
        <el-button link type="primary" @click="router.push('/logs')">日志</el-button>
      </div>
      <div class="activity-card panel">
        <div class="activity-icon amber"><el-icon><Bell /></el-icon></div>
        <div>
          <span>今日告警次数</span>
          <strong>{{ counts.today_alerts || 0 }}</strong>
        </div>
        <el-button link type="primary" @click="router.push('/logs?tab=notification')">记录</el-button>
      </div>
    </section>

    <section class="grid-2 section-gap">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">域名状态分布</h3>
            <p class="panel-subtitle">按当前监控状态统计</p>
          </div>
          <el-tag type="info" effect="plain" size="small">共 {{ counts.domain_total || 0 }} 个</el-tag>
        </div>
        <div class="panel-body">
          <ChartBox :option="domainPie" height="290px" />
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">SSL 证书状态分布</h3>
            <p class="panel-subtitle">按最近一次检测结果统计</p>
          </div>
          <el-tag type="info" effect="plain" size="small">共 {{ counts.ssl_total || 0 }} 个</el-tag>
        </div>
        <div class="panel-body">
          <ChartBox :option="sslPie" height="290px" />
        </div>
      </div>
    </section>

    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">最近 30 天检测记录</h3>
          <p class="panel-subtitle">每日域名与 SSL 检测次数及失败情况</p>
        </div>
        <div class="chart-legend">
          <span><i style="background:#0f9d8a"></i>域名检测</span>
          <span><i style="background:#0ea5e9"></i>SSL 检测</span>
          <span><i style="background:#ef4444"></i>失败</span>
        </div>
      </div>
      <div class="panel-body">
        <ChartBox :option="trendOption" height="320px" />
      </div>
    </section>

    <section class="grid-2 section-gap">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">未来 30 天到期域名</h3>
            <p class="panel-subtitle">需及时续费的域名</p>
          </div>
          <el-button link type="primary" @click="router.push('/domains')">全部域名</el-button>
        </div>
        <el-table :data="data.upcoming_domains" class="dm-table" size="small" :show-header="true">
          <el-table-column prop="name" label="域名" min-width="150">
            <template #default="{ row }"><span class="mono">{{ row.name }}</span></template>
          </el-table-column>
          <el-table-column label="到期时间" width="118">
            <template #default="{ row }">{{ formatDate(row.expires_at) }}</template>
          </el-table-column>
          <el-table-column label="剩余" width="92" align="right">
            <template #default="{ row }"><span :class="daysClass(row.days_remaining)">{{ daysText(row.days_remaining) }}</span></template>
          </el-table-column>
        </el-table>
        <div v-if="!data.upcoming_domains.length" class="empty-state">未来 30 天没有即将到期的域名</div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">未来 30 天到期证书</h3>
            <p class="panel-subtitle">需续期或替换的 SSL 证书</p>
          </div>
          <el-button link type="primary" @click="router.push('/certificates')">全部证书</el-button>
        </div>
        <el-table :data="data.upcoming_certs" class="dm-table" size="small" :show-header="true">
          <el-table-column prop="domain" label="域名" min-width="150">
            <template #default="{ row }"><span class="mono">{{ row.domain }}:{{ row.port }}</span></template>
          </el-table-column>
          <el-table-column label="到期时间" width="118">
            <template #default="{ row }">{{ formatDate(row.not_after) }}</template>
          </el-table-column>
          <el-table-column label="剩余" width="92" align="right">
            <template #default="{ row }"><span :class="daysClass(row.days_remaining)">{{ daysText(row.days_remaining) }}</span></template>
          </el-table-column>
        </el-table>
        <div v-if="!data.upcoming_certs.length" class="empty-state">未来 30 天没有即将到期的证书</div>
      </div>
    </section>

    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">最近告警记录</h3>
          <p class="panel-subtitle">域名、证书及系统异常通知</p>
        </div>
        <el-button link type="primary" @click="router.push('/logs?tab=notification')">查看全部</el-button>
      </div>
      <div class="alert-list">
        <div v-for="alert in data.recent_alerts" :key="alert.id" class="alert-row">
          <div class="alert-main">
            <span class="alert-title">{{ alert.title || eventTypes[alert.event] || alert.event }}</span>
            <span class="alert-subject">{{ alert.subject }}</span>
          </div>
          <div class="alert-meta">
            <el-tag :type="alert.status === 'success' ? 'success' : alert.status === 'failed' ? 'danger' : 'info'" size="small" effect="plain">
              {{ alert.status === 'success' ? '已发送' : alert.status === 'failed' ? '发送失败' : '发送中' }}
            </el-tag>
            <span>{{ alert.channel_name }}</span>
            <span>{{ formatDateTime(alert.created_at) }}</span>
          </div>
        </div>
        <div v-if="!data.recent_alerts.length" class="empty-state">暂无告警记录</div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  Bell, CircleCheck, DataLine, Lock, Monitor, Refresh, Timer, Warning, WarningFilled,
} from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { DashboardData } from '@/api/types'
import ChartBox from '@/components/ChartBox.vue'
import { dark } from '@/stores/theme'
import {
  certStatus, daysClass, daysText, domainStatus, eventTypes, formatDate, formatDateTime,
} from '@/utils/status'

const router = useRouter()
const loading = ref(false)
const data = ref<DashboardData>({
  counts: {}, domain_status: [], ssl_status: [],
  trends: { dates: [], domain: [], ssl: [], failed: [] },
  upcoming_domains: [], upcoming_certs: [], recent_alerts: [],
})
const updatedAt = ref('—')
let timer: number | undefined

const counts = computed(() => data.value.counts)
const domainCards = computed(() => [
  { label: '域名总数', value: counts.value.domain_total || 0, foot: `${counts.value.domain_normal || 0} 个状态正常`, color: '#0f9d8a', icon: Monitor },
  { label: '正常域名', value: counts.value.domain_normal || 0, foot: `${counts.value.domain_pending || 0} 个待检测`, color: '#10b981', icon: CircleCheck },
  { label: '即将到期域名', value: counts.value.domain_expiring || 0, foot: '进入预警周期', color: '#f59e0b', icon: Warning },
  { label: '已过期域名', value: counts.value.domain_expired || 0, foot: `${counts.value.domain_failed || 0} 个查询失败`, color: '#ef4444', icon: Timer },
])
const sslCards = computed(() => [
  { label: 'SSL 证书总数', value: counts.value.ssl_total || 0, foot: 'HTTPS 监控端点', color: '#0ea5e9', icon: Lock },
  { label: '正常证书', value: counts.value.ssl_normal || 0, foot: '证书链有效', color: '#10b981', icon: CircleCheck },
  { label: '即将到期证书', value: counts.value.ssl_expiring || 0, foot: '建议尽快续期', color: '#f59e0b', icon: Warning },
  { label: '已过期证书', value: counts.value.ssl_expired || 0, foot: `${counts.value.ssl_invalid || 0} 个证书异常`, color: '#ef4444', icon: Timer },
])

const pieColors: Record<string, string> = {
  normal: '#10b981', expiring: '#f59e0b', expired: '#ef4444',
  query_failed: '#be123c', pending: '#94a3b8', unreachable: '#dc2626',
  invalid: '#e11d48', failed: '#f97316',
}

function pieOption(rows: { status: string; count: number }[], labels: Record<string, { label: string }>, center: string) {
  const items = rows
    .filter((row) => row.count > 0)
    .map((row) => ({
      value: row.count,
      name: labels[row.status]?.label || row.status,
      itemStyle: { color: pieColors[row.status] || '#94a3b8' },
    }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}<br/>{c} ({d}%)' },
    legend: {
      bottom: 0,
      icon: 'circle',
      itemWidth: 8,
      itemHeight: 8,
      textStyle: { color: dark.value ? '#94a3b8' : '#64748b', fontSize: 11 },
    },
    graphic: {
      type: 'text', left: 'center', top: '34%',
      style: { text: center, fill: dark.value ? '#e5edf7' : '#152238', fontSize: 26, fontWeight: 700, textAlign: 'center' },
    },
    series: [{
      type: 'pie', radius: ['53%', '72%'], center: ['50%', '43%'], avoidLabelOverlap: true,
      itemStyle: { borderRadius: 6, borderColor: dark.value ? '#101a29' : '#fff', borderWidth: 3 },
      label: { show: false }, labelLine: { show: false },
      data: items.length ? items : [{ value: 1, name: '暂无数据', itemStyle: { color: dark.value ? '#1e293b' : '#e2e8f0' } }],
    }],
  }
}

const domainPie = computed(() => pieOption(data.value.domain_status, domainStatus, String(counts.value.domain_total || 0)))
const sslPie = computed(() => pieOption(data.value.ssl_status, certStatus, String(counts.value.ssl_total || 0)))

const trendOption = computed(() => {
  const axis = dark.value ? '#64748b' : '#94a3b8'
  const split = dark.value ? '#1d2a3d' : '#eef2f7'
  const shortDates = data.value.trends.dates.map((d) => d.slice(5))
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 12, right: 18, top: 24, bottom: 24, containLabel: true },
    xAxis: {
      type: 'category', boundaryGap: false, data: shortDates,
      axisLine: { lineStyle: { color: split } },
      axisTick: { show: false },
      axisLabel: { color: axis, fontSize: 10, interval: 4 },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      splitLine: { lineStyle: { color: split, type: 'dashed' } },
      axisLabel: { color: axis, fontSize: 10 },
    },
    series: [
      {
        name: '域名检测', type: 'line', smooth: true, showSymbol: false, data: data.value.trends.domain,
        lineStyle: { width: 2.5, color: '#0f9d8a' },
        areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(15,157,138,.22)' }, { offset: 1, color: 'rgba(15,157,138,0)' }] } },
      },
      {
        name: 'SSL 检测', type: 'line', smooth: true, showSymbol: false, data: data.value.trends.ssl,
        lineStyle: { width: 2.5, color: '#0ea5e9' },
        areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(14,165,233,.18)' }, { offset: 1, color: 'rgba(14,165,233,0)' }] } },
      },
      {
        name: '失败', type: 'line', smooth: true, showSymbol: false, data: data.value.trends.failed,
        lineStyle: { width: 1.8, color: '#ef4444', type: 'dashed' },
      },
    ],
  }
})

async function load() {
  loading.value = true
  try {
    data.value = await api.get<DashboardData>('/dashboard')
    updatedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = window.setInterval(load, 60000)
})
onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped>
.update-hint {
  color: var(--dm-text-muted);
  font-size: 11.5px;
}
.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
}
.activity-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}
.activity-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 17px 20px;
  box-shadow: var(--dm-shadow);
}
.activity-icon {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  font-size: 18px;
  flex: 0 0 40px;
}
.activity-icon.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
.activity-icon.teal { background: rgba(15, 157, 138, 0.1); color: #0f9d8a; }
.activity-icon.amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
.activity-card > div:nth-child(2) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.activity-card span {
  color: var(--dm-text-secondary);
  font-size: 12px;
}
.activity-card strong {
  font-size: 22px;
  line-height: 1.1;
  letter-spacing: -0.03em;
}
.activity-card .el-button {
  margin-left: auto;
}
.chart-legend {
  display: flex;
  gap: 14px;
  font-size: 11px;
  color: var(--dm-text-secondary);
  flex-wrap: wrap;
}
.chart-legend span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.chart-legend i {
  width: 14px;
  height: 3px;
  border-radius: 2px;
  display: inline-block;
}
.alert-list {
  padding: 4px 20px 12px;
}
.alert-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 0;
  border-bottom: 1px solid var(--dm-border);
}
.alert-row:last-child {
  border-bottom: 0;
}
.alert-main {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.alert-title {
  font-size: 13px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.alert-subject {
  color: var(--dm-text-muted);
  font-size: 11.5px;
}
.alert-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  color: var(--dm-text-muted);
  font-size: 11px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
@media (max-width: 900px) {
  .activity-grid {
    grid-template-columns: 1fr;
  }
  .alert-row {
    align-items: flex-start;
    flex-direction: column;
    gap: 7px;
  }
  .alert-meta {
    justify-content: flex-start;
  }
}
</style>
