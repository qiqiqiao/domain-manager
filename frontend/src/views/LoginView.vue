<template>
  <div class="login-page">
    <div class="login-visual">
      <div class="visual-glow glow-a"></div>
      <div class="visual-glow glow-b"></div>
      <div class="visual-content">
        <div class="visual-brand">
          <span class="visual-mark">DM</span>
          <span>Domain Manager</span>
        </div>
        <h1>把域名与证书<br />牢牢握在手中</h1>
        <p class="visual-lead">域名到期、SSL 证书、ACME 自动续期与多平台告警，一站式管理。</p>
        <div class="feature-list">
          <div class="feature">
            <span class="feature-icon">◎</span>
            <div><strong>域名到期监控</strong><span>RDAP 优先，WHOIS 兜底</span></div>
          </div>
          <div class="feature">
            <span class="feature-icon">⌁</span>
            <div><strong>SSL 证书检测</strong><span>到期、链、域名匹配全覆盖</span></div>
          </div>
          <div class="feature">
            <span class="feature-icon">↻</span>
            <div><strong>ACME 自动续期</strong><span>Let's Encrypt HTTP-01 / DNS-01</span></div>
          </div>
          <div class="feature">
            <span class="feature-icon">◈</span>
            <div><strong>多渠道路告警</strong><span>Telegram · 飞书 · Lark · 钉钉</span></div>
          </div>
        </div>
      </div>
      <div class="visual-footer">单二进制部署 · SQLite 本地存储 · 数据完全自持</div>
    </div>

    <div class="login-form-side">
      <div class="login-form-wrap">
        <div class="mobile-brand">
          <span class="visual-mark">DM</span>
          <span>Domain Manager</span>
        </div>
        <div class="form-heading">
          <span class="eyebrow">ADMIN CONSOLE</span>
          <h2>{{ step === 'password' ? '登录管理后台' : '二次认证' }}</h2>
          <p>{{ step === 'password' ? '使用管理员账号访问域名与证书监控控制台' : '请输入身份验证器生成的动态验证码，或使用恢复码' }}</p>
        </div>

        <el-alert v-if="expired" title="登录状态已失效，请重新登录" type="warning" :closable="false" show-icon class="expired-alert" />

        <el-form v-if="step === 'password'" ref="formRef" :model="form" :rules="rules" label-position="top" @keyup.enter="submit">
          <el-form-item label="管理员账号" prop="username">
            <el-input v-model="form.username" size="large" placeholder="请输入用户名" :prefix-icon="User" autocomplete="username" />
          </el-form-item>
          <el-form-item label="登录密码" prop="password">
            <el-input
              v-model="form.password"
              size="large"
              type="password"
              show-password
              placeholder="请输入密码"
              :prefix-icon="Lock"
              autocomplete="current-password"
            />
          </el-form-item>
          <el-button class="login-button" type="primary" size="large" :loading="loading" @click="submit">
            登录控制台
          </el-button>
        </el-form>

        <el-form v-else ref="totpFormRef" :model="totpForm" :rules="totpRules" label-position="top" @keyup.enter="submitTOTP">
          <div class="totp-account">
            <span>正在验证账号</span>
            <strong>{{ form.username }}</strong>
          </div>
          <el-form-item label="动态验证码或恢复码" prop="code">
            <el-input
              ref="totpInputRef"
              v-model="totpForm.code"
              size="large"
              placeholder="6 位动态验证码，或一次性恢复码"
              :prefix-icon="Key"
              autocomplete="one-time-code"
              spellcheck="false"
            />
          </el-form-item>
          <el-button class="login-button" type="primary" size="large" :loading="loading" @click="submitTOTP">
            验证并登录
          </el-button>
          <el-button class="back-login" link @click="backToPassword">返回上一步</el-button>
        </el-form>

        <div v-if="step === 'password'" class="secure-tip">
          <el-icon><Lock /></el-icon>
          <span>首次运行的初始密码会在服务启动终端中输出，请登录后立即修改。</span>
        </div>
      </div>
      <div class="login-copyright">Domain Manager v1.0 · 本地优先的监控管理平台</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { nextTick, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'
import type { FormInstance, FormRules } from 'element-plus'
import { Key, Lock, User } from '@element-plus/icons-vue'
import { login, verifyTOTP, type LoginResponse } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const formRef = ref<FormInstance>()
const totpFormRef = ref<FormInstance>()
const totpInputRef = ref<{ focus: () => void }>()
const loading = ref(false)
const expired = route.query.expired === '1'
const step = ref<'password' | 'totp'>('password')
const challengeToken = ref('')

const form = reactive({ username: '', password: '' })
const rules: FormRules = {
  username: [{ required: true, message: '请输入管理员账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入登录密码', trigger: 'blur' }],
}
const totpForm = reactive({ code: '' })
const totpRules: FormRules = {
  code: [{ required: true, message: '请输入动态验证码或恢复码', trigger: 'blur' }],
}

async function finishLogin(data: LoginResponse) {
  ElMessage.success('登录成功')
  if (data.must_change_password) {
    await router.replace('/settings?tab=security')
    return
  }
  const redirect = typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/') ? route.query.redirect : '/'
  await router.replace(redirect)
}

async function submit() {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  loading.value = true
  try {
    const data = await login(form.username, form.password)
    if (data.totp_required) {
      if (!data.challenge_token) throw new Error('二次认证会话无效')
      challengeToken.value = data.challenge_token
      totpForm.code = ''
      step.value = 'totp'
      await nextTick()
      totpInputRef.value?.focus()
      return
    }
    await finishLogin(data)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || '登录失败，请检查账号密码')
  } finally {
    loading.value = false
  }
}

async function submitTOTP() {
  if (!totpFormRef.value) return
  const valid = await totpFormRef.value.validate().catch(() => false)
  if (!valid) return
  loading.value = true
  try {
    const data = await verifyTOTP(challengeToken.value, totpForm.code)
    await finishLogin(data)
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || '验证码无效，请重试')
  } finally {
    loading.value = false
  }
}

function backToPassword() {
  step.value = 'password'
  challengeToken.value = ''
  totpForm.code = ''
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  min-height: 100dvh;
  display: grid;
  grid-template-columns: 1.08fr 1fr;
  background: #f6f8fb;
  /* The login screen is intentionally always light, even when dark mode is
     persisted from a previous authenticated session. */
  --el-text-color-primary: #0f172a;
  --el-text-color-regular: #344256;
  --el-text-color-secondary: #718096;
  --el-text-color-placeholder: #a0aec0;
  --el-border-color: #dfe6ef;
  --el-border-color-light: #e5eaf1;
  --el-fill-color-blank: #ffffff;
  --el-fill-color-light: #f2f6fa;
  --el-bg-color: #ffffff;
  --el-bg-color-overlay: #ffffff;
}

.login-visual {
  position: relative;
  overflow: hidden;
  background: radial-gradient(circle at 20% 20%, #0f766e 0%, transparent 48%),
    radial-gradient(circle at 85% 75%, #0c4a6e 0%, transparent 50%),
    linear-gradient(145deg, #07111f 0%, #0a1b2d 60%, #071521 100%);
  color: #e6f4f1;
  padding: 54px 64px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.visual-glow {
  position: absolute;
  border-radius: 50%;
  filter: blur(18px);
  opacity: 0.28;
}
.glow-a {
  width: 420px;
  height: 420px;
  background: #2dd4bf;
  top: -160px;
  right: -120px;
}
.glow-b {
  width: 380px;
  height: 380px;
  background: #0ea5e9;
  bottom: -180px;
  left: -100px;
}
.visual-content {
  position: relative;
  z-index: 2;
  max-width: 560px;
}
.visual-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: #f0fdfa;
  margin-bottom: 54px;
}
.visual-mark {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  background: linear-gradient(135deg, #2dd4bf, #0ea5e9);
  color: #fff;
  font-size: 13px;
  font-weight: 800;
  box-shadow: 0 10px 30px rgba(45, 212, 191, 0.3);
}
.visual-content h1 {
  font-size: clamp(36px, 4vw, 54px);
  line-height: 1.14;
  letter-spacing: -0.035em;
  margin: 0;
  color: #fff;
}
.visual-lead {
  color: #94a3b8;
  font-size: 15px;
  line-height: 1.8;
  max-width: 430px;
  margin: 20px 0 34px;
}
.feature-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.feature {
  display: flex;
  gap: 12px;
  padding: 14px;
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.045);
  border: 1px solid rgba(255, 255, 255, 0.07);
  backdrop-filter: blur(8px);
}
.feature-icon {
  flex: 0 0 30px;
  height: 30px;
  border-radius: 9px;
  display: grid;
  place-items: center;
  background: rgba(45, 212, 191, 0.16);
  color: #5eead4;
  font-size: 15px;
}
.feature div {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.feature strong {
  color: #e2e8f0;
  font-size: 13px;
}
.feature span {
  color: #7c8da3;
  font-size: 11.5px;
  line-height: 1.5;
}
.visual-footer {
  position: absolute;
  z-index: 2;
  bottom: 30px;
  left: 64px;
  color: #64748b;
  font-size: 11.5px;
  letter-spacing: 0.02em;
}

.login-form-side {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px;
  position: relative;
  background:
    radial-gradient(circle at 80% 0%, rgba(15, 157, 138, 0.08), transparent 42%),
    #f7f9fc;
}
.login-form-wrap {
  width: 100%;
  max-width: 390px;
  animation: login-in 0.45s ease both;
}
@keyframes login-in {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
.mobile-brand {
  display: none;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  margin-bottom: 34px;
  color: #0f172a;
}
.eyebrow {
  display: inline-block;
  font-size: 10px;
  letter-spacing: 0.18em;
  color: #0f9d8a;
  font-weight: 750;
  margin-bottom: 12px;
}
.form-heading h2 {
  font-size: 30px;
  letter-spacing: -0.035em;
  margin: 0;
  color: #0f172a;
}
.form-heading p {
  color: #718096;
  font-size: 13.5px;
  margin: 10px 0 28px;
}
.expired-alert {
  margin-bottom: 18px;
}
.login-button {
  width: 100%;
  height: 46px;
  margin-top: 4px;
  font-size: 14.5px;
  font-weight: 650;
  border-radius: 10px;
  box-shadow: 0 10px 24px rgba(15, 157, 138, 0.22);
}
.totp-account {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 13px;
  margin-bottom: 18px;
  border-radius: 10px;
  background: #eef3f8;
  color: #718096;
  font-size: 12px;
}
.totp-account strong {
  color: #0f172a;
  font-size: 13px;
  font-weight: 650;
}
.back-login {
  display: block;
  margin: 14px auto 0;
  color: #718096;
}
.secure-tip {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  color: #8a97a8;
  font-size: 11.5px;
  line-height: 1.6;
  background: #eef3f8;
  border-radius: 10px;
  padding: 11px 12px;
  margin-top: 24px;
}
.secure-tip .el-icon {
  margin-top: 1px;
  color: #0f9d8a;
}
.login-copyright {
  position: absolute;
  bottom: 24px;
  color: #a0aec0;
  font-size: 11px;
}

.login-form-side :deep(.el-form-item__label) {
  color: #344256;
  font-weight: 600;
  font-size: 12.5px;
}
.login-form-side :deep(.el-input__wrapper) {
  background: #fff;
  box-shadow: 0 0 0 1px #dfe6ef inset;
  border-radius: 10px;
  padding: 2px 14px;
}
.login-form-side :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px #0f9d8a inset, 0 0 0 4px rgba(15, 157, 138, 0.1);
}

@media (max-width: 1020px) {
  .login-page {
    grid-template-columns: 1fr;
  }
  .login-visual {
    display: none;
  }
  .login-form-side {
    background:
      radial-gradient(circle at 50% 0%, rgba(15, 157, 138, 0.12), transparent 45%),
      #f7f9fc;
  }
  .mobile-brand {
    display: flex;
  }
}

@media (max-width: 520px) {
  .login-form-side {
    padding: 28px 22px;
  }
  .form-heading h2 {
    font-size: 26px;
  }
}
</style>
