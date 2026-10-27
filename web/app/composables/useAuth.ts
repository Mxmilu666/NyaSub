import type { AuthUser } from '~/types/api'

export function useAuth() {
  const user = useState<AuthUser | null>('nyasub-user', () => null)
  const checked = useState<boolean>('nyasub-auth-checked', () => false)
  const initialized = useState<boolean | null>('nyasub-initialized', () => null)

  async function loadStatus(force = false): Promise<boolean> {
    if (initialized.value !== null && !force) return initialized.value
    try {
      const data = await $fetch<{ initialized: boolean }>('/api/auth/status')
      initialized.value = data.initialized
    } catch {
      initialized.value = false
    }
    return initialized.value
  }

  async function refreshUser(): Promise<AuthUser | null> {
    try {
      const data = await $fetch<{ user: AuthUser }>('/api/auth/me')
      user.value = data.user
    } catch {
      user.value = null
    }
    checked.value = true
    return user.value
  }

  async function login(username: string, password: string): Promise<AuthUser> {
    const data = await useApi().api<{ user: AuthUser }>('/api/auth/login', {
      method: 'POST',
      body: { username, password }
    })
    user.value = data.user
    initialized.value = true
    checked.value = true
    return data.user
  }

  async function setup(username: string, password: string): Promise<AuthUser> {
    const data = await useApi().api<{ user: AuthUser }>('/api/auth/setup', {
      method: 'POST',
      body: { username, password }
    })
    user.value = data.user
    initialized.value = true
    checked.value = true
    return data.user
  }

  async function logout(): Promise<void> {
    try {
      await useApi().api('/api/auth/logout', { method: 'POST' })
    } finally {
      user.value = null
      checked.value = true
    }
  }

  function clear(): void {
    user.value = null
    checked.value = true
  }

  return { user, checked, initialized, loadStatus, refreshUser, login, setup, logout, clear }
}
