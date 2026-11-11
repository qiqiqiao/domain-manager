import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { auth, loadMe } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { title: '登录', public: true },
  },
  {
    path: '/',
    component: () => import('@/layout/AppLayout.vue'),
    children: [
      { path: '', name: 'dashboard', component: () => import('@/views/DashboardView.vue'), meta: { title: '仪表盘' } },
      { path: 'domains', name: 'domains', component: () => import('@/views/DomainsView.vue'), meta: { title: '域名管理' } },
      { path: 'certificates', name: 'certificates', component: () => import('@/views/CertificatesView.vue'), meta: { title: 'SSL 证书管理' } },
      { path: 'apply', name: 'apply', component: () => import('@/views/ApplyView.vue'), meta: { title: '证书申请' } },
      { path: 'notifications', name: 'notifications', component: () => import('@/views/NotificationsView.vue'), meta: { title: '告警通知' } },
      { path: 'logs', name: 'logs', component: () => import('@/views/LogsView.vue'), meta: { title: '监控日志' } },
      { path: 'settings', name: 'settings', component: () => import('@/views/SettingsView.vue'), meta: { title: '系统设置' } },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  document.title = `${String(to.meta.title || '管理后台')} · Domain Manager`
  if (to.meta.public) {
    if (to.name === 'login' && auth.user) return '/'
    return true
  }
  const user = await loadMe()
  if (!user) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  return true
})

export default router
