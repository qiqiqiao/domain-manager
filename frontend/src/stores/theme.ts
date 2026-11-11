import { ref } from 'vue'

const stored = localStorage.getItem('dm_theme')
export const dark = ref(stored === 'dark')

export function applyTheme() {
  const root = document.documentElement
  root.classList.toggle('dark', dark.value)
  localStorage.setItem('dm_theme', dark.value ? 'dark' : 'light')
}

export function toggleTheme() {
  dark.value = !dark.value
  applyTheme()
}

applyTheme()
