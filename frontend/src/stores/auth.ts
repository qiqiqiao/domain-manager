import { reactive } from 'vue'
import { api } from '@/api/client'
import type { User } from '@/api/types'

export interface LoginResponse {
  totp_required: boolean
  challenge_token?: string
  user?: User
  csrf_token?: string
  expires_at: string
  must_change_password?: boolean
}

export const auth = reactive({
  user: null as User | null,
  csrf: sessionStorage.getItem('dm_csrf') || '',
  ready: false,
})

export function setSession(data: { user: User; csrf_token: string }) {
  auth.user = data.user
  auth.csrf = data.csrf_token
  sessionStorage.setItem('dm_csrf', data.csrf_token)
}

export function clearSession() {
  auth.user = null
  auth.csrf = ''
  auth.ready = true
  sessionStorage.removeItem('dm_csrf')
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const data = await api.post<LoginResponse>('/auth/login', { username, password })
  if (!data.totp_required) {
    if (!data.user || !data.csrf_token) throw new Error('登录响应无效')
    setSession({ user: data.user, csrf_token: data.csrf_token })
    auth.ready = true
  }
  return data
}

export async function verifyTOTP(challengeToken: string, code: string): Promise<LoginResponse> {
  const data = await api.post<LoginResponse>('/auth/login/totp', {
    challenge_token: challengeToken,
    code,
  })
  if (!data.user || !data.csrf_token) throw new Error('二次认证响应无效')
  setSession({ user: data.user, csrf_token: data.csrf_token })
  auth.ready = true
  return data
}

export async function loadMe(): Promise<User | null> {
  if (auth.user) return auth.user
  try {
    const data = await api.get<{ user: User; csrf_token: string }>('/auth/me')
    setSession(data)
    auth.ready = true
    return data.user
  } catch {
    clearSession()
    return null
  }
}

export async function logout() {
  try {
    await api.post('/auth/logout')
  } catch {
    // Ignore network errors during logout; local state is cleared anyway.
  }
  clearSession()
}

export async function changePassword(current: string, next: string) {
  await api.put('/auth/password', { current_password: current, new_password: next })
  clearSession()
}

window.addEventListener('dm:unauthorized', () => {
  if (auth.user) {
    clearSession()
    if (location.pathname !== '/login') {
      location.href = '/login?expired=1'
    }
  }
})
