<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">告警通知</h1>
        <p class="page-subtitle">配置 Telegram、Lark、飞书与钉钉通知渠道，并为不同事件绑定通知规则。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="Refresh" :loading="loading" @click="loadAll">刷新</el-button>
        <el-button type="primary" :icon="Plus" @click="openCreate">添加渠道</el-button>
      </div>
    </div>

    <el-tabs v-model="activeTab" class="page-tabs">
      <el-tab-pane label="通知渠道" name="channels">
        <div class="channel-grid">
          <div v-for="channel in channels" :key="channel.id" class="panel channel-card">
            <div class="channel-head">
              <div class="channel-type" :class="channel.type">
                <el-icon><component :is="channelIcon(channel.type)" /></el-icon>
              </div>
              <div class="channel-title">
                <strong>{{ channel.name }}</strong>
                <span>{{ channelTypes[channel.type] || channel.type }}</span>
              </div>
              <el-switch
                :model-value="channel.enabled"
                size="small"
                @change="(value: boolean) => toggleChannel(channel, value)"
              />
            </div>

            <div class="channel-preview">
              <div class="preview-row"><span>目标</span><code>{{ configPreview(channel) }}</code></div>
              <div class="preview-row">
                <span>最近测试</span>
                <em v-if="channel.last_test_at">
                  {{ formatDateTime(channel.last_test_at) }}
                  <el-tag :type="channel.last_test_ok ? 'success' : 'danger'" size="small" effect="plain">
                    {{ channel.last_test_ok ? '成功' : '失败' }}
                  </el-tag>
                </em>
                <em v-else class="muted">尚未测试</em>
              </div>
              <el-tooltip v-if="channel.last_error" :content="channel.last_error" placement="top">
                <div class="channel-error"><el-icon><WarningFilled /></el-icon>{{ channel.last_error }}</div>
              </el-tooltip>
            </div>

            <div class="channel-actions">
              <el-button size="small" :loading="testing === channel.id" @click="testChannel(channel)">发送测试</el-button>
              <el-button size="small" :icon="Edit" @click="openEdit(channel)">编辑</el-button>
              <el-button size="small" type="danger" plain :icon="Delete" @click="removeChannel(channel)">删除</el-button>
            </div>
          </div>
          <button class="add-channel-card" @click="openCreate">
            <el-icon><Plus /></el-icon>
            <span>添加通知渠道</span>
            <small>Telegram / Lark / 飞书 / 钉钉</small>
          </button>
        </div>
        <div v-if="!channels.length && !loading" class="empty-state panel">尚未配置任何通知渠道</div>
      </el-tab-pane>

      <el-tab-pane label="告警规则" name="rules">
        <div class="panel">
          <div class="panel-header">
            <div>
              <h3 class="panel-title">事件通知规则</h3>
              <p class="panel-subtitle">为不同事件选择一个或多个通知渠道。未选择渠道的事件不会发送通知。</p>
            </div>
            <div class="rules-actions">
              <el-button link type="primary" @click="router.push('/settings?tab=general')">修改到期阈值</el-button>
              <el-button type="primary" :loading="savingRules" @click="saveRules">保存规则</el-button>
            </div>
          </div>
          <div class="table-wrap">
            <el-table :data="rules" class="dm-table">
              <el-table-column label="事件" min-width="190">
                <template #default="{ row }">
                  <div class="rule-event">
                    <strong>{{ eventTypes[row.event] || row.event }}</strong>
                    <span>{{ row.description }}</span>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="通知渠道" min-width="260">
                <template #default="{ row }">
                  <el-select v-model="row.channel_ids" multiple collapse-tags collapse-tags-tooltip placeholder="选择通知渠道" style="width: 100%">
                    <el-option v-for="channel in channels" :key="channel.id" :label="channel.name" :value="channel.id" :disabled="!channel.enabled" />
                  </el-select>
                </template>
              </el-table-column>
              <el-table-column label="去重窗口" width="150">
                <template #default="{ row }">
                  <el-input-number v-model="row.dedup_hours" :min="0" :max="8760" controls-position="right" style="width: 120px" />
                  <span class="unit">小时</span>
                </template>
              </el-table-column>
              <el-table-column label="启用" width="90" align="center">
                <template #default="{ row }"><el-switch v-model="row.enabled" /></template>
              </el-table-column>
            </el-table>
          </div>
        </div>
        <div class="alert-box section-gap">
          通知失败会自动重试（默认最多 5 次，可在系统设置中调整），同一告警按事件、对象、阈值和到期日期去重，避免无限重复发送。
          去重窗口设为 0 表示同一告警永久去重；域名和证书恢复后，系统会发送恢复通知。
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="dialogVisible" :title="editing ? '编辑通知渠道' : '添加通知渠道'" width="560px" destroy-on-close append-to-body>
      <el-form ref="formRef" :model="form" :rules="formRules" label-position="top">
        <div class="form-grid">
          <el-form-item label="渠道名称" prop="name">
            <el-input v-model="form.name" placeholder="例如：运维告警群" />
          </el-form-item>
          <el-form-item label="渠道类型">
            <el-select v-model="form.type" style="width: 100%" :disabled="!!editing" @change="onTypeChange">
              <el-option label="Telegram" value="telegram" />
              <el-option label="Lark（国际版）" value="lark" />
              <el-option label="飞书" value="feishu" />
              <el-option label="钉钉" value="dingtalk" />
            </el-select>
          </el-form-item>
        </div>

        <template v-if="form.type === 'telegram'">
          <el-form-item label="Bot Token" prop="config.bot_token">
            <el-input v-model="form.config.bot_token" type="password" show-password placeholder="123456:ABC-DEF..." />
            <div class="form-hint">可在 Telegram 中通过 @BotFather 创建机器人获取 Token。</div>
          </el-form-item>
          <div class="form-grid">
            <el-form-item label="Chat ID" prop="config.chat_id">
              <el-input v-model="form.config.chat_id" placeholder="-1001234567890" />
            </el-form-item>
            <el-form-item label="Topic ID（可选）">
              <el-input v-model="form.config.thread_id" placeholder="论坛群组的话题 ID" />
            </el-form-item>
          </div>
        </template>

        <template v-else>
          <el-form-item label="机器人 Webhook URL" prop="config.webhook_url">
            <el-input v-model="form.config.webhook_url" placeholder="https://..." />
            <div class="form-hint">仅允许 HTTPS 公网地址。Webhook 中的密钥会脱敏显示，编辑时保留占位符不会覆盖原值。</div>
          </el-form-item>
          <el-form-item label="签名密钥（可选）">
            <el-input v-model="form.config.secret" type="password" show-password placeholder="启用加签时填写" />
          </el-form-item>
          <el-form-item v-if="form.type === 'lark' || form.type === 'feishu'" label="消息格式">
            <div class="switch-row">
              <el-switch v-model="form.config.use_card" />
              <span>使用交互式消息卡片（推荐）</span>
            </div>
          </el-form-item>
        </template>

        <el-form-item label="渠道状态">
          <div class="switch-row">
            <el-switch v-model="form.enabled" />
            <span>启用该通知渠道</span>
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveChannel">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import type { FormInstance, FormRules } from 'element-plus'
import {
  ChatDotRound, Delete, Edit, Message, Plus, Promotion, Refresh, WarningFilled,
} from '@element-plus/icons-vue'
import { api, showError } from '@/api/client'
import type { Channel, NotificationRule } from '@/api/types'
import { channelTypes, eventTypes, formatDateTime } from '@/utils/status'

const router = useRouter()
const activeTab = ref('channels')
const channels = ref<Channel[]>([])
const rules = ref<NotificationRule[]>([])
const loading = ref(false)
const testing = ref<number | null>(null)
const savingRules = ref(false)

const dialogVisible = ref(false)
const editing = ref<Channel | null>(null)
const saving = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({
  name: '',
  type: 'telegram',
  enabled: true,
  config: {} as Record<string, any>,
})
const formRules: FormRules = {
  name: [{ required: true, message: '请输入渠道名称', trigger: 'blur' }],
  'config.bot_token': [{ required: true, message: '请输入 Bot Token', trigger: 'blur' }],
  'config.chat_id': [{ required: true, message: '请输入 Chat ID', trigger: 'blur' }],
  'config.webhook_url': [{ required: true, message: '请输入 Webhook URL', trigger: 'blur' }],
}

function channelIcon(type: string) {
  if (type === 'telegram') return Promotion
  if (type === 'dingtalk') return ChatDotRound
  return Message
}

function configPreview(channel: Channel) {
  const cfg = channel.config || {}
  if (channel.type === 'telegram') return `Chat ID: ${cfg.chat_id || '—'}`
  const url = String(cfg.webhook_url || '')
  try {
    return new URL(url.replace('••••', 'masked')).host || 'Webhook 已配置'
  } catch {
    return 'Webhook 已配置'
  }
}

async function loadAll() {
  loading.value = true
  try {
    const [channelData, ruleData] = await Promise.all([
      api.get<Channel[]>('/notifications'),
      api.get<NotificationRule[]>('/notification-rules'),
    ])
    channels.value = channelData
    rules.value = ruleData
  } catch (error) {
    showError(error)
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  Object.assign(form, { name: '', type: 'telegram', enabled: true, config: {} })
  dialogVisible.value = true
}

function openEdit(channel: Channel) {
  editing.value = channel
  form.name = channel.name
  form.type = channel.type
  form.enabled = channel.enabled
  form.config = { ...channel.config }
  dialogVisible.value = true
}

function onTypeChange() {
  form.config = {}
}

async function saveChannel() {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  saving.value = true
  try {
    if (editing.value) {
      await api.put(`/notifications/${editing.value.id}`, {
        name: form.name, type: form.type, enabled: form.enabled, config: form.config,
      })
      ElMessage.success('通知渠道已更新')
    } else {
      await api.post('/notifications', {
        name: form.name, type: form.type, enabled: form.enabled, config: form.config,
      })
      ElMessage.success('通知渠道已添加')
    }
    dialogVisible.value = false
    loadAll()
  } catch (error) {
    showError(error)
  } finally {
    saving.value = false
  }
}

async function toggleChannel(channel: Channel, enabled: boolean) {
  try {
    await api.put(`/notifications/${channel.id}`, {
      name: channel.name, type: channel.type, enabled, config: channel.config,
    })
    channel.enabled = enabled
    ElMessage.success(enabled ? '渠道已启用' : '渠道已禁用')
  } catch (error) {
    showError(error)
  }
}

async function testChannel(channel: Channel) {
  testing.value = channel.id
  try {
    const result = await api.post<{ success: boolean; error?: string }>(`/notifications/${channel.id}/test`)
    if (result.success) ElMessage.success('测试消息已发送，请检查目标群组')
    else ElMessage.error(`发送失败：${result.error || '未知错误'}`)
    loadAll()
  } catch (error) {
    showError(error)
  } finally {
    testing.value = null
  }
}

async function removeChannel(channel: Channel) {
  try {
    await ElMessageBox.confirm(`确定删除通知渠道「${channel.name}」吗？相关告警规则会同步移除该渠道。`, '删除渠道', {
      confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning',
    })
  } catch {
    return
  }
  try {
    await api.delete(`/notifications/${channel.id}`)
    ElMessage.success('通知渠道已删除')
    loadAll()
  } catch (error) {
    showError(error)
  }
}

async function saveRules() {
  savingRules.value = true
  try {
    const data = await api.put<NotificationRule[]>('/notification-rules', {
      rules: rules.value.map((rule) => ({
        event: rule.event, channel_ids: rule.channel_ids,
        enabled: rule.enabled, dedup_hours: rule.dedup_hours,
      })),
    })
    rules.value = data
    ElMessage.success('告警规则已保存')
  } catch (error) {
    showError(error)
  } finally {
    savingRules.value = false
  }
}

onMounted(loadAll)
</script>

<style scoped>
.page-tabs {
  margin-top: -4px;
}
.page-tabs :deep(.el-tabs__header) {
  margin-bottom: 16px;
}
.page-tabs :deep(.el-tabs__item) {
  font-weight: 600;
}
.channel-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}
.channel-card {
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  box-shadow: var(--dm-shadow);
  transition: transform 0.18s, box-shadow 0.18s;
}
.channel-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--dm-shadow-hover);
}
.channel-head {
  display: flex;
  align-items: center;
  gap: 11px;
}
.channel-type {
  width: 38px;
  height: 38px;
  border-radius: 11px;
  display: grid;
  place-items: center;
  background: rgba(14, 165, 233, 0.1);
  color: #0ea5e9;
  font-size: 18px;
  flex: 0 0 38px;
}
.channel-type.telegram { background: rgba(14, 165, 233, 0.12); color: #0ea5e9; }
.channel-type.lark { background: rgba(15, 157, 138, 0.12); color: #0f9d8a; }
.channel-type.feishu { background: rgba(59, 130, 246, 0.12); color: #3b82f6; }
.channel-type.dingtalk { background: rgba(245, 158, 11, 0.13); color: #f59e0b; }
.channel-title {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  flex: 1;
}
.channel-title strong {
  font-size: 13.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.channel-title span {
  font-size: 10.5px;
  color: var(--dm-text-muted);
}
.channel-preview {
  background: var(--dm-panel-2);
  border: 1px solid var(--dm-border);
  border-radius: 10px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.preview-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  font-size: 11px;
}
.preview-row > span {
  color: var(--dm-text-muted);
  flex: 0 0 auto;
}
.preview-row code {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 10.5px;
  color: var(--dm-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.preview-row em {
  font-style: normal;
  color: var(--dm-text-secondary);
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10.5px;
}
.channel-error {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--dm-danger);
  font-size: 10.5px;
  line-height: 1.4;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.channel-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: auto;
}
.add-channel-card {
  border: 1.5px dashed var(--dm-border);
  background: transparent;
  border-radius: var(--dm-radius);
  min-height: 210px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 7px;
  color: var(--dm-text-muted);
  cursor: pointer;
  transition: all 0.18s;
  font-family: inherit;
}
.add-channel-card:hover {
  border-color: var(--dm-primary);
  color: var(--dm-primary);
  background: var(--dm-primary-soft);
}
.add-channel-card .el-icon {
  font-size: 26px;
}
.add-channel-card span {
  font-size: 13px;
  font-weight: 600;
}
.add-channel-card small {
  font-size: 10.5px;
}
.rules-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}
.rule-event {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.rule-event strong {
  font-size: 12.5px;
}
.rule-event span {
  font-size: 10.5px;
  color: var(--dm-text-muted);
}
.unit {
  font-size: 11px;
  color: var(--dm-text-muted);
  margin-left: 4px;
}
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.switch-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: var(--dm-text-secondary);
}
@media (max-width: 1200px) {
  .channel-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .channel-grid, .form-grid { grid-template-columns: 1fr; }
  .add-channel-card { min-height: 130px; }
}
</style>
