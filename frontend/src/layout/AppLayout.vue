<template>
  <div class="app-shell">
    <div v-if="mobileOpen" class="mobile-overlay" @click="mobileOpen = false"></div>
    <aside class="sidebar" :class="{ collapsed, 'mobile-open': mobileOpen }">
      <div class="brand" @click="router.push('/')">
        <div class="brand-mark">DM</div>
        <div v-show="!collapsed || mobileOpen" class="brand-copy">
          <strong>Domain Manager</strong>
          <span>域名 · 证书 · 告警</span>
        </div>
      </div>

      <el-menu
        :default-active="route.path"
        router
        :collapse="collapsed && !mobileOpen"
        class="side-menu"
        background-color="transparent"
        text-color="var(--dm-sidebar-text)"
        active-text-color="#ffffff"
      >
        <el-menu-item index="/">
          <el-icon><Odometer /></el-icon>
          <template #title>仪表盘</template>
        </el-menu-item>
        <el-menu-item index="/domains">
          <el-icon><Monitor /></el-icon>
          <template #title>域名管理</template>
        </el-menu-item>
        <el-menu-item index="/certificates">
          <el-icon><Lock /></el-icon>
          <template #title>SSL 证书管理</template>
        </el-menu-item>
        <el-menu-item index="/apply">
          <el-icon><DocumentAdd /></el-icon>
          <template #title>证书申请</template>
        </el-menu-item>
        <el-menu-item index="/notifications">
          <el-icon><Bell /></el-icon>
          <template #title>告警通知</template>
        </el-menu-item>
        <el-menu-item index="/logs">
          <el-icon><Tickets /></el-icon>
          <template #title>监控日志</template>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <template #title>系统设置</template>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-foot">
        <div v-show="!collapsed || mobileOpen" class="system-chip">
          <span class="status-dot" :class="{ offline: !healthy }"></span>
          {{ healthy ? '服务运行正常' : '服务连接异常' }}
        </div>
        <el-button class="collapse-btn" text circle @click="toggleCollapse">
          <el-icon><Expand v-if="collapsed" /><Fold v-else /></el-icon>
        </el-button>
      </div>
    </aside>

    <div class="main-area">
      <header class="topbar">
        <div class="topbar-left">
          <el-button class="mobile-menu" text circle @click="mobileOpen = true">
            <el-icon><Expand /></el-icon>
          </el-button>
          <div class="page-crumb">
            <span class="crumb-root">控制台</span>
            <el-icon class="crumb-sep"><ArrowRight /></el-icon>
            <span class="crumb-current">{{ route.meta.title }}</span>
          </div>
        </div>
        <div class="topbar-right">
          <div class="health-pill">
            <span class="status-dot" :class="{ offline: !healthy }"></span>
            {{ healthy ? '运行中' : '连接异常' }}
          </div>
          <el-tooltip :content="dark ? '切换浅色模式' : '切换深色模式'">
            <el-button text circle @click="toggleTheme">
              <el-icon><Sunny v-if="dark" /><Moon v-else /></el-icon>
            </el-button>
          </el-tooltip>
          <el-dropdown trigger="click" @command="handleCommand">
            <button class="user-chip">
              <span class="avatar">{{ initial }}</span>
              <span class="user-name">{{ auth.user?.username }}</span>
              <el-icon><ArrowDown /></el-icon>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="settings" :icon="Setting">系统设置</el-dropdown-item>
                <el-dropdown-item command="logout" :icon="SwitchButton" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <div v-if="auth.user?.must_change_password" class="password-banner">
        <el-icon><WarningFilled /></el-icon>
        <span>当前使用初始密码，为保障系统安全，请立即修改管理员密码。</span>
        <el-button link type="warning" @click="router.push('/settings?tab=security')">立即修改</el-button>
      </div>

      <main class="content">
        <router-view v-slot="{ Component }">
          <transition name="page-fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import { ElMessageBox } from 'element-plus/es/components/message-box/index.mjs'
import {
  ArrowDown, ArrowRight, Bell, DocumentAdd, Expand, Fold, Lock, Monitor, Moon,
  Odometer, Setting, Sunny, SwitchButton, Tickets, WarningFilled,
} from '@element-plus/icons-vue'
import { auth, logout } from '@/stores/auth'
import { dark, toggleTheme } from '@/stores/theme'

const router = useRouter()
const route = useRoute()
const collapsed = ref(localStorage.getItem('dm_collapsed') === '1')
const mobileOpen = ref(false)
const healthy = ref(true)
let healthTimer: number | undefined

const initial = computed(() => (auth.user?.username || 'A').slice(0, 1).toUpperCase())

function toggleCollapse() {
  collapsed.value = !collapsed.value
  localStorage.setItem('dm_collapsed', collapsed.value ? '1' : '0')
}

async function checkHealth() {
  try {
    const response = await fetch('/health', { cache: 'no-store' })
    healthy.value = response.ok
  } catch {
    healthy.value = false
  }
}

async function handleCommand(command: string) {
  if (command === 'settings') {
    router.push('/settings')
    return
  }
  if (command === 'logout') {
    try {
      await ElMessageBox.confirm('确定要退出登录吗？', '退出登录', {
        confirmButtonText: '退出', cancelButtonText: '取消', type: 'warning',
      })
    } catch {
      return
    }
    await logout()
    ElMessage.success('已退出登录')
    router.replace('/login')
  }
}

watch(() => route.path, () => {
  mobileOpen.value = false
})

onMounted(() => {
  checkHealth()
  healthTimer = window.setInterval(checkHealth, 60000)
})

onBeforeUnmount(() => {
  if (healthTimer) window.clearInterval(healthTimer)
})
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  min-height: 100dvh;
}

.sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  width: 244px;
  background: linear-gradient(180deg, var(--dm-sidebar) 0%, var(--dm-sidebar-2) 100%);
  display: flex;
  flex-direction: column;
  z-index: 50;
  transition: width 0.22s ease, transform 0.22s ease;
  border-right: 1px solid rgba(255, 255, 255, 0.04);
}

.sidebar.collapsed {
  width: 76px;
}

.brand {
  height: 74px;
  padding: 0 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  overflow: hidden;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.brand-mark {
  flex: 0 0 38px;
  width: 38px;
  height: 38px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  color: #fff;
  font-weight: 800;
  font-size: 13px;
  letter-spacing: -0.03em;
  background: linear-gradient(135deg, #14b8a6, #0ea5e9);
  box-shadow: 0 8px 20px rgba(20, 184, 166, 0.25);
}

.brand-copy {
  display: flex;
  flex-direction: column;
  min-width: 140px;
}
.brand-copy strong {
  color: #f1f5f9;
  font-size: 14px;
  letter-spacing: -0.01em;
  white-space: nowrap;
}
.brand-copy span {
  color: #64748b;
  font-size: 11px;
  margin-top: 3px;
  white-space: nowrap;
}

.side-menu {
  border-right: 0 !important;
  padding: 14px 10px;
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
}

.side-menu :deep(.el-menu-item) {
  height: 46px;
  line-height: 46px;
  border-radius: 11px;
  margin-bottom: 5px;
  font-size: 13.5px;
  font-weight: 520;
  transition: background 0.18s, color 0.18s;
}
.side-menu :deep(.el-menu-item .el-icon) {
  font-size: 18px;
}
.side-menu :deep(.el-menu-item:hover) {
  background: rgba(255, 255, 255, 0.06) !important;
  color: #e2e8f0;
}
.side-menu :deep(.el-menu-item.is-active) {
  background: linear-gradient(90deg, rgba(20, 184, 166, 0.24), rgba(14, 165, 233, 0.12)) !important;
  color: #fff !important;
  box-shadow: inset 3px 0 0 #2dd4bf;
}
.side-menu :deep(.el-menu-item.is-active .el-icon) {
  color: #2dd4bf;
}

.sidebar-foot {
  padding: 12px 14px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
  min-height: 58px;
}
.system-chip {
  font-size: 11px;
  color: #64748b;
  white-space: nowrap;
  overflow: hidden;
}
.collapse-btn {
  color: #64748b !important;
  flex: 0 0 auto;
}
.collapse-btn:hover {
  color: #cbd5e1 !important;
}

.main-area {
  margin-left: 244px;
  min-height: 100vh;
  min-height: 100dvh;
  transition: margin-left 0.22s ease;
  display: flex;
  flex-direction: column;
}
.sidebar.collapsed ~ .main-area {
  margin-left: 76px;
}

.topbar {
  height: 68px;
  flex: 0 0 68px;
  position: sticky;
  top: 0;
  z-index: 40;
  background: color-mix(in srgb, var(--dm-panel) 88%, transparent);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--dm-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 26px;
  gap: 16px;
}

.topbar-left,
.topbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
}
.page-crumb {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 13px;
}
.crumb-root {
  color: var(--dm-text-muted);
}
.crumb-sep {
  font-size: 11px;
  color: var(--dm-text-muted);
}
.crumb-current {
  color: var(--dm-text);
  font-weight: 600;
}

.health-pill {
  font-size: 12px;
  color: var(--dm-text-secondary);
  border: 1px solid var(--dm-border);
  background: var(--dm-panel-2);
  padding: 6px 11px;
  border-radius: 999px;
  display: flex;
  align-items: center;
}
.status-dot.offline {
  background: var(--dm-danger);
  box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.14);
}

.user-chip {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 5px 9px 5px 5px;
  border-radius: 999px;
  border: 1px solid var(--dm-border);
  background: var(--dm-panel);
  color: var(--dm-text);
  cursor: pointer;
  transition: border-color 0.18s, box-shadow 0.18s;
}
.user-chip:hover {
  border-color: var(--dm-primary);
  box-shadow: 0 0 0 3px var(--dm-primary-soft);
}
.avatar {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  background: linear-gradient(135deg, #14b8a6, #0ea5e9);
  color: #fff;
  font-size: 12px;
  font-weight: 700;
}
.user-name {
  font-size: 13px;
  font-weight: 550;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.password-banner {
  margin: 16px 26px -4px;
  border: 1px solid rgba(245, 158, 11, 0.35);
  background: rgba(245, 158, 11, 0.08);
  color: #b45309;
  border-radius: 12px;
  padding: 10px 14px;
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 13px;
  flex-wrap: wrap;
}
html.dark .password-banner {
  color: #fbbf24;
}

.content {
  padding: 24px 26px 40px;
  flex: 1;
}

.mobile-menu {
  display: none;
}
.mobile-overlay {
  display: none;
}

.page-fade-enter-active,
.page-fade-leave-active {
  transition: opacity 0.16s ease;
}
.page-fade-enter-from,
.page-fade-leave-to {
  opacity: 0;
}

@media (max-width: 900px) {
  .sidebar,
  .sidebar.collapsed {
    width: 244px;
    transform: translateX(-102%);
    box-shadow: 20px 0 50px rgba(0, 0, 0, 0.3);
  }
  .sidebar.mobile-open {
    transform: translateX(0);
  }
  .main-area,
  .sidebar.collapsed ~ .main-area {
    margin-left: 0;
  }
  .mobile-menu {
    display: inline-flex;
  }
  .mobile-overlay {
    display: block;
    position: fixed;
    inset: 0;
    z-index: 45;
    background: rgba(2, 6, 23, 0.55);
    backdrop-filter: blur(2px);
  }
  .topbar {
    padding: 0 16px;
  }
  .content {
    padding: 18px 16px 32px;
  }
  .user-name {
    display: none;
  }
  .health-pill {
    display: none;
  }
  .password-banner {
    margin: 12px 16px -2px;
  }
}

@media (max-width: 560px) {
  .page-crumb .crumb-root,
  .crumb-sep {
    display: none;
  }
}
</style>
