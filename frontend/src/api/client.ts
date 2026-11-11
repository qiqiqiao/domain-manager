import axios, { type AxiosRequestConfig } from 'axios'
import { ElMessage } from 'element-plus/es/components/message/index.mjs'

interface ApiResponse<T> {
  code: number
  message: string
  data: T
}

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 120000,
  withCredentials: true,
})

http.interceptors.request.use((config) => {
  const method = (config.method || 'get').toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = sessionStorage.getItem('dm_csrf') || ''
    if (csrf) config.headers['X-CSRF-Token'] = csrf
  }
  return config
})

http.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    if (status === 401) {
      window.dispatchEvent(new CustomEvent('dm:unauthorized'))
    }
    return Promise.reject(error)
  },
)

export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const message = error.response?.data?.message
    if (message) return message
    if (error.code === 'ECONNABORTED') return '请求超时，请稍后重试'
    if (!error.response) return '无法连接服务器'
    return `请求失败（HTTP ${error.response.status}）`
  }
  if (error instanceof Error) return error.message
  return '操作失败'
}

async function request<T>(config: AxiosRequestConfig): Promise<T> {
  const response = await http.request<ApiResponse<T>>(config)
  return response.data.data
}

export const api = {
  get<T>(url: string, params?: Record<string, unknown>) {
    return request<T>({ method: 'GET', url, params })
  },
  post<T>(url: string, data?: unknown) {
    return request<T>({ method: 'POST', url, data })
  },
  put<T>(url: string, data?: unknown) {
    return request<T>({ method: 'PUT', url, data })
  },
  delete<T>(url: string) {
    return request<T>({ method: 'DELETE', url })
  },
  upload<T>(url: string, form: FormData) {
    return request<T>({ method: 'POST', url, data: form })
  },
  async blob(url: string, params?: Record<string, unknown>): Promise<Blob> {
    const response = await http.get(url, { params, responseType: 'blob' })
    return response.data
  },
  async postBlob(url: string, data?: unknown): Promise<Blob> {
    const response = await http.post(url, data, { responseType: 'blob' })
    return response.data
  },
}

export function showError(error: unknown, fallback = '操作失败') {
  ElMessage.error(errorMessage(error) || fallback)
}

export default http
