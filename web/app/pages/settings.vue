<script setup lang="ts">
import type { AppSettings, SessionInfo } from '~/types/api'
import { ApiError } from '~/composables/useApi'

useHead({ title: '设置' })

const { api, download, ensureCsrf } = useApi()
const auth = useAuth()
const { formatDate, timeAgo } = useFormat()
const toast = useToast()

const settings = ref<AppSettings | null>(null)
const sessions = ref<SessionInfo[]>([])
const loading = ref(true)

async function load() {
  loading.value = true
  try {
    const [settingsData, sessionData] = await Promise.all([
      api<AppSettings>('/api/settings'),
      api<{ sessions: SessionInfo[] }>('/api/auth/sessions')
    ])
    settings.value = settingsData
    sessions.value = sessionData.sessions
  } catch (error) {
    toast.add({ title: '加载设置失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    loading.value = false
  }
}

// --- password --------------------------------------------------------------
const passwordForm = reactive({ current: '', next: '', confirm: '' })
const passwordSaving = ref(false)
const passwordError = ref('')
const passwordSuccess = ref('')

async function changePassword() {
  passwordError.value = ''
  passwordSuccess.value = ''
  if (passwordForm.next.length < 10) {
    passwordError.value = '新密码至少需要 10 个字符。'
    return
  }
  if (passwordForm.next !== passwordForm.confirm) {
    passwordError.value = '两次输入的新密码不一致。'
    return
  }
  passwordSaving.value = true
  try {
    await api('/api/auth/password', {
      method: 'PUT',
      body: { current_password: passwordForm.current, new_password: passwordForm.next }
    })
    passwordSuccess.value = '密码已更新，其他会话已被撤销。'
    passwordForm.current = ''
    passwordForm.next = ''
    passwordForm.confirm = ''
    await load()
  } catch (error) {
    passwordError.value = error instanceof ApiError ? error.message : '修改密码失败。'
  } finally {
    passwordSaving.value = false
  }
}

// --- sessions --------------------------------------------------------------
const revoking = ref<string | null>(null)

async function revokeSession(session: SessionInfo) {
  revoking.value = session.id
  try {
    await api(`/api/auth/sessions/${session.id}`, { method: 'DELETE' })
    if (session.current) {
      auth.clear()
      toast.add({ title: '当前会话已撤销', icon: 'i-lucide-log-out' })
      await navigateTo('/login')
      return
    }
    toast.add({ title: '会话已撤销', icon: 'i-lucide-shield-off' })
    await load()
  } catch (error) {
    toast.add({ title: '无法撤销会话', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    revoking.value = null
  }
}

// --- log level -------------------------------------------------------------
const logLevelItems = [
  { label: 'Debug', value: 'debug' },
  { label: 'Info', value: 'info' },
  { label: 'Warn', value: 'warn' },
  { label: 'Error', value: 'error' }
]
const changingLogLevel = ref(false)

async function changeLogLevel(value: string) {
  if (!settings.value) return
  changingLogLevel.value = true
  try {
    const result = await api<{ log_level: string }>('/api/settings/log-level', { method: 'PUT', body: { level: value } })
    settings.value.log_level = result.log_level
    toast.add({ title: `日志级别已设为 ${result.log_level}`, icon: 'i-lucide-scroll-text' })
  } catch (error) {
    toast.add({ title: '无法更改日志级别', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
    await load()
  } finally {
    changingLogLevel.value = false
  }
}

// --- backup ----------------------------------------------------------------
const backupBusy = ref(false)
const restoreFile = ref<File | null>(null)
const restoreOpen = ref(false)
const restoreError = ref('')
const restoreText = ref('')

function downloadBackup() {
  backupBusy.value = true
  download('/api/backup', 'nyasub-backup.json').catch((error) => {
    toast.add({ title: '备份失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  }).finally(() => {
    backupBusy.value = false
  })
}

function pickRestoreFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  if (file.size > 40 * 1024 * 1024) {
    toast.add({ title: '备份文件过大', description: '最大为 40 MiB。', color: 'error', icon: 'i-lucide-triangle-alert' })
    return
  }
  restoreFile.value = file
  restoreOpen.value = true
  restoreError.value = ''
}

async function restoreBackup() {
  if (!restoreFile.value) return
  backupBusy.value = true
  restoreError.value = ''
  try {
    restoreText.value = await restoreFile.value.text()
    let csrf = await ensureCsrf()
    let response = await fetch('/api/backup/restore', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: restoreText.value
    })
    if (response.status === 403) {
      csrf = await ensureCsrf(true)
      response = await fetch('/api/backup/restore', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: restoreText.value
      })
    }
    const body = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(body?.error?.message || '恢复失败。')
    restoreOpen.value = false
    auth.clear()
    toast.add({ title: '备份已恢复', description: '请使用备份中的凭据重新登录。', icon: 'i-lucide-database-backup' })
    await navigateTo('/login')
  } catch (error) {
    restoreError.value = (error as Error).message
  } finally {
    backupBusy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="mb-6">
      <h1 class="text-2xl font-semibold tracking-tight">设置</h1>
      <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">账户、会话、运行时日志与数据迁移。</p>
    </div>

    <div class="grid gap-6 lg:grid-cols-3">
      <div class="space-y-6 lg:col-span-2">
        <UCard>
          <template #header>
            <h2 class="font-semibold">修改密码</h2>
            <p class="text-xs text-neutral-500">修改密码会保留当前会话并撤销其他会话。</p>
          </template>
          <form class="grid gap-4 sm:grid-cols-2" @submit.prevent="changePassword">
            <UAlert v-if="passwordError" class="sm:col-span-2" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="passwordError" />
            <UAlert v-if="passwordSuccess" class="sm:col-span-2" color="success" variant="subtle" icon="i-lucide-check-circle-2" :title="passwordSuccess" />
            <UFormField label="当前密码" class="sm:col-span-2">
              <UInput v-model="passwordForm.current" type="password" autocomplete="current-password" class="w-full" />
            </UFormField>
            <UFormField label="新密码" hint="至少 10 个字符">
              <UInput v-model="passwordForm.next" type="password" autocomplete="new-password" class="w-full" />
            </UFormField>
            <UFormField label="确认新密码">
              <UInput v-model="passwordForm.confirm" type="password" autocomplete="new-password" class="w-full" />
            </UFormField>
            <div class="sm:col-span-2">
              <UButton type="submit" icon="i-lucide-key-round" :loading="passwordSaving">更新密码</UButton>
            </div>
          </form>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex items-center justify-between">
              <div>
                <h2 class="font-semibold">会话</h2>
                <p class="text-xs text-neutral-500">会话 Token 以 SHA-256 哈希形式保存。</p>
              </div>
              <UButton size="xs" icon="i-lucide-refresh-cw" color="neutral" variant="ghost" :loading="loading" @click="load">刷新</UButton>
            </div>
          </template>
          <div v-if="loading" class="space-y-2">
            <div v-for="i in 2" :key="i" class="h-16 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
          </div>
          <div v-else class="space-y-3">
            <div v-for="session in sessions" :key="session.id" class="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
              <div class="flex flex-wrap items-start justify-between gap-2">
                <div class="min-w-0">
                  <div class="flex items-center gap-2">
                    <UIcon name="i-lucide-monitor" class="size-4 text-neutral-400" />
                    <span class="text-sm font-medium">{{ session.ip || '未知 IP' }}</span>
                    <UBadge v-if="session.current" color="success" variant="subtle" size="sm">当前会话</UBadge>
                  </div>
                  <p class="mt-1 truncate text-xs text-neutral-500">{{ session.user_agent || '未知客户端' }}</p>
                  <p class="mt-1 text-[11px] text-neutral-400">
                    创建于 {{ formatDate(session.created_at) }} · 最近活动 {{ timeAgo(session.last_seen_at) }} · 过期时间 {{ formatDate(session.expires_at) }}
                  </p>
                </div>
                <UButton
                  size="xs"
                  color="error"
                  variant="ghost"
                  icon="i-lucide-shield-off"
                  :loading="revoking === session.id"
                  @click="revokeSession(session)"
                >
                  撤销
                </UButton>
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">数据备份与恢复</h2>
            <p class="text-xs text-neutral-500">可迁移的 JSON 快照，包含节点、订阅配置、密码哈希和订阅 Token 哈希。</p>
          </template>
          <UAlert
            color="warning"
            variant="subtle"
            icon="i-lucide-shield-alert"
            title="备份文件包含敏感数据"
            description="请加密并离线保存。恢复会覆盖整个数据库，并要求重新登录。"
          />
          <div class="mt-4 flex flex-wrap gap-2">
            <UButton icon="i-lucide-download" color="neutral" variant="subtle" :loading="backupBusy" @click="downloadBackup">下载备份</UButton>
            <label class="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium hover:bg-neutral-50 dark:border-neutral-700 dark:hover:bg-neutral-900">
              <UIcon name="i-lucide-upload" class="size-4" />
              恢复备份
              <input type="file" accept=".json,application/json" class="hidden" @change="pickRestoreFile" />
            </label>
          </div>
        </UCard>
      </div>

      <div class="space-y-6">
        <UCard>
          <template #header><h2 class="font-semibold">应用信息</h2></template>
          <dl class="space-y-3 text-sm">
            <div>
              <dt class="text-xs text-neutral-500">版本</dt>
              <dd class="mono">{{ settings?.version || '—' }}</dd>
            </div>
            <div>
              <dt class="text-xs text-neutral-500">基础 URL</dt>
              <dd class="break-all mono text-xs">{{ settings?.base_url || '—' }}</dd>
            </div>
            <div>
              <dt class="text-xs text-neutral-500">监听地址</dt>
              <dd class="mono text-xs">{{ settings?.listen || '—' }}</dd>
            </div>
            <div>
              <dt class="text-xs text-neutral-500">数据目录</dt>
              <dd class="break-all mono text-xs">{{ settings?.data_dir || '—' }}</dd>
            </div>
            <div class="flex items-center justify-between">
              <dt class="text-xs text-neutral-500">安全 Cookie</dt>
              <dd>
                <UBadge :color="settings?.secure_cookies ? 'success' : 'warning'" variant="subtle" size="sm">
                  {{ settings?.secure_cookies ? '已启用' : '已禁用' }}
                </UBadge>
              </dd>
            </div>
            <div class="flex items-center justify-between">
              <dt class="text-xs text-neutral-500">会话有效期</dt>
              <dd class="text-xs">{{ settings?.session_ttl_hours }} 小时</dd>
            </div>
          </dl>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">日志</h2>
            <p class="text-xs text-neutral-500">运行时级别在重启前有效。APP_LOG_LEVEL 设置启动默认值。</p>
          </template>
          <USelect
            :model-value="settings?.log_level"
            :items="logLevelItems"
            :loading="changingLogLevel"
            class="w-full"
            @update:model-value="(v) => changeLogLevel(String(v))"
          />
          <p class="mt-2 text-xs text-neutral-500">请求日志会脱敏订阅 Token，绝不包含节点凭据。</p>
        </UCard>
      </div>
    </div>

    <UModal v-model:open="restoreOpen" title="恢复备份" :ui="{ content: 'max-w-md' }">
      <template #body>
        <div class="space-y-4">
          <UAlert color="error" variant="subtle" icon="i-lucide-triangle-alert" title="这会替换当前全部数据" description="用户、会话、节点、链式代理、订阅配置和 Token 都会被快照覆盖。" />
          <p class="text-sm text-neutral-600 dark:text-neutral-300">
            确定从 <span class="font-medium">{{ restoreFile?.name }}</span> 恢复？
          </p>
          <UAlert v-if="restoreError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="restoreError" />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="restoreOpen = false">取消</UButton>
          <UButton color="error" icon="i-lucide-database-backup" :loading="backupBusy" @click="restoreBackup">恢复</UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
