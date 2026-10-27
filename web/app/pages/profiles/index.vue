<script setup lang="ts">
import type { ProfileSummary } from '~/types/api'
import { ApiError } from '~/composables/useApi'

useHead({ title: '订阅配置' })

const { api, download } = useApi()
const { timeAgo, formatDate } = useFormat()
const toast = useToast()


const profiles = ref<ProfileSummary[]>([])
const loading = ref(true)

async function load() {
  loading.value = true
  try {
    const data = await api<{ profiles: ProfileSummary[] }>('/api/profiles')
    profiles.value = data.profiles
  } catch (error) {
    toast.add({ title: '加载订阅配置失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    loading.value = false
  }
}

const previewOpen = ref(false)
const previewTitle = ref('')
const previewYaml = ref('')
const previewLoading = ref(false)
const previewETag = ref('')

async function openPreview(profile: ProfileSummary) {
  previewOpen.value = true
  previewTitle.value = profile.name
  previewYaml.value = ''
  previewETag.value = ''
  previewLoading.value = true
  try {
    const response = await fetch(`/api/profiles/${profile.id}/preview`, { credentials: 'same-origin' })
    if (!response.ok) {
      let message = '预览失败。'
      try { message = (await response.json())?.error?.message || message } catch { /* ignore */ }
      throw new Error(message)
    }
    previewYaml.value = await response.text()
    previewETag.value = response.headers.get('ETag') || ''
  } catch (error) {
    toast.add({ title: '预览失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    previewLoading.value = false
  }
}

async function copyText(text: string, label = '已复制') {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ title: label, icon: 'i-lucide-clipboard-check' })
  } catch {
    toast.add({ title: '无法访问剪贴板', description: '请从输入框手动复制。', color: 'warning', icon: 'i-lucide-clipboard-x' })
  }
}

function downloadProfile(profile: ProfileSummary) {
  download(`/api/profiles/${profile.id}/download`, `${profile.name}.yaml`).catch((error) => {
    toast.add({ title: '下载失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  })
}

// --- subscription token ----------------------------------------------------
const tokenOpen = ref(false)
const tokenProfile = ref<ProfileSummary | null>(null)
const issuedURL = ref('')
const issuedXrayURL = ref('')
const issuing = ref(false)
const currentToken = computed(() => tokenProfile.value?.token ?? null)
const currentURL = computed(() => issuedURL.value || currentToken.value?.url || '')
const currentXrayURL = computed(() => issuedXrayURL.value || currentToken.value?.xray_url || (currentURL.value ? `${currentURL.value}?format=xray` : ''))


function openToken(profile: ProfileSummary) {
  tokenProfile.value = profile
  issuedURL.value = ''
  issuedXrayURL.value = ''
  tokenOpen.value = true
}

async function issueToken() {
  if (!tokenProfile.value) return
  issuing.value = true
  try {
    const result = await api<{ url: string; xray_url: string; token_id: string }>(`/api/profiles/${tokenProfile.value.id}/tokens`, { method: 'POST' })
    issuedURL.value = result.url
    issuedXrayURL.value = result.xray_url
    tokenProfile.value.token = {
      id: result.token_id,
      created_at: new Date().toISOString(),
      last_used_at: null,
      revoked_at: null,
      active: true,
      url: result.url,
      xray_url: result.xray_url
    }
    toast.add({ title: '订阅链接已生成', icon: 'i-lucide-key-round' })
    await load()
    if (!tokenProfile.value) return
    const refreshed = profiles.value.find((p) => p.id === tokenProfile.value!.id)
    if (refreshed) tokenProfile.value = refreshed
  } catch (error) {
    toast.add({ title: 'Token 生成失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    issuing.value = false
  }
}

async function revokeToken() {
  if (!tokenProfile.value?.token) return
  const token = tokenProfile.value.token
  try {
    await api(`/api/subscription-tokens/${token.id}`, { method: 'DELETE' })
    tokenProfile.value.token = null
    issuedURL.value = ''
    issuedXrayURL.value = ''
    toast.add({ title: '订阅 Token 已撤销', icon: 'i-lucide-shield-off' })
    await load()
  } catch (error) {
    toast.add({ title: '撤销失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  }
}

// --- delete profile --------------------------------------------------------
const deleteOpen = ref(false)
const deleteTarget = ref<ProfileSummary | null>(null)
const deleting = ref(false)
const deleteError = ref('')

function askDelete(profile: ProfileSummary) {
  deleteTarget.value = profile
  deleteError.value = ''
  deleteOpen.value = true
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  deleteError.value = ''
  try {
    await api(`/api/profiles/${deleteTarget.value.id}`, { method: 'DELETE' })
    toast.add({ title: '订阅配置已删除', icon: 'i-lucide-trash-2' })
    deleteOpen.value = false
    await load()
  } catch (error) {
    deleteError.value = error instanceof ApiError ? error.message : '删除失败。'
  } finally {
    deleting.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">订阅配置</h1>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
          每个配置生成一份确定性的 Mihomo 订阅。
        </p>
      </div>
      <UButton to="/profiles/new" icon="i-lucide-plus">新建订阅配置</UButton>
    </div>

    <div v-if="loading" class="space-y-3">
      <div v-for="i in 3" :key="i" class="h-32 animate-pulse rounded-xl bg-neutral-100 dark:bg-neutral-800" />
    </div>
    <div v-else-if="!profiles.length" class="rounded-xl border border-dashed border-neutral-300 py-16 text-center dark:border-neutral-700">
      <UIcon name="i-lucide-file-code-2" class="mx-auto size-10 text-neutral-300 dark:text-neutral-700" />
      <h2 class="mt-3 font-medium">还没有订阅配置</h2>
      <p class="mt-1 text-sm text-neutral-500">选择节点、链式代理、策略组和规则，然后发布订阅。</p>
      <UButton to="/profiles/new" class="mt-4" icon="i-lucide-plus">创建订阅配置</UButton>
    </div>
    <div v-else class="grid gap-4 lg:grid-cols-2">
      <UCard v-for="profile in profiles" :key="profile.id">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="truncate text-base font-semibold">{{ profile.name }}</h2>
              <UBadge v-if="profile.token" color="success" variant="subtle" size="sm">订阅已启用</UBadge>
              <UBadge v-else color="neutral" variant="subtle" size="sm">无 Token</UBadge>
              <UBadge v-if="profile.template === 'acl4ssr'" color="info" variant="subtle" size="sm">ACL4SSR</UBadge>
            </div>
            <p class="mt-1 line-clamp-2 text-sm text-neutral-500 dark:text-neutral-400">
              {{ profile.description || '暂无描述。' }}
            </p>
          </div>
          <UButton :to="`/profiles/${profile.id}/edit`" icon="i-lucide-pencil" size="sm" color="neutral" variant="subtle">编辑</UButton>
        </div>

        <div class="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
          <div class="rounded-lg bg-neutral-50 p-2 dark:bg-neutral-900">
            <div class="text-base font-semibold">{{ profile.node_count }}</div>
            <div class="text-neutral-500">节点</div>
          </div>
          <div class="rounded-lg bg-neutral-50 p-2 dark:bg-neutral-900">
            <div class="text-base font-semibold">{{ profile.chain_count }}</div>
            <div class="text-neutral-500">链式代理</div>
          </div>
          <div class="rounded-lg bg-neutral-50 p-2 dark:bg-neutral-900">
            <div class="truncate text-xs font-semibold">
              {{ profile.default_exit_type ? (profile.default_exit_type === 'chain' ? '链式代理' : '节点') : '无' }}
            </div>
            <div class="text-neutral-500">默认出口</div>
          </div>
        </div>

        <div class="mt-4 flex flex-wrap gap-2 border-t border-neutral-100 pt-4 dark:border-neutral-900">
          <UButton size="xs" icon="i-lucide-key-round" :color="profile.token ? 'warning' : 'primary'" variant="subtle" @click="openToken(profile)">
            {{ profile.token ? '轮换链接' : '创建链接' }}
          </UButton>
          <UButton size="xs" icon="i-lucide-eye" color="neutral" variant="subtle" @click="openPreview(profile)">预览</UButton>
          <UButton size="xs" icon="i-lucide-download" color="neutral" variant="subtle" @click="downloadProfile(profile)">下载</UButton>
          <UButton size="xs" icon="i-lucide-trash-2" color="error" variant="ghost" class="ml-auto" @click="askDelete(profile)">删除</UButton>
        </div>

        <div class="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-neutral-400">
          <span>更新于 {{ timeAgo(profile.updated_at) }}</span>
          <span v-if="profile.token?.last_used_at">最近拉取于 {{ timeAgo(profile.token.last_used_at) }}</span>
          <span v-else-if="profile.token">从未拉取</span>
        </div>
      </UCard>
    </div>

    <UModal v-model:open="previewOpen" :title="`${previewTitle} · YAML 预览`" :ui="{ content: 'max-w-4xl' }">
      <template #body>
        <div class="space-y-3">
          <div class="flex flex-wrap items-center gap-2">
            <UButton size="xs" icon="i-lucide-copy" color="neutral" variant="subtle" :disabled="!previewYaml" @click="copyText(previewYaml, 'YAML 已复制')">复制 YAML</UButton>
            <span v-if="previewETag" class="mono truncate text-[11px] text-neutral-400">ETag {{ previewETag }}</span>
          </div>
          <div v-if="previewLoading" class="h-64 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
          <pre v-else class="yaml-preview">{{ previewYaml }}</pre>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end">
          <UButton color="neutral" variant="ghost" @click="previewOpen = false">关闭</UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="tokenOpen" title="订阅链接" :ui="{ content: 'max-w-2xl' }">
      <template #body>
        <div class="space-y-4">
          <UAlert
            color="warning"
            variant="subtle"
            icon="i-lucide-shield-alert"
            title="订阅链接属于敏感凭据"
            description="任何拿到链接的人都能读取该配置。请勿公开分享；轮换后旧链接会立即失效。"
          />

          <div v-if="currentToken" class="rounded-lg border border-neutral-200 p-3 text-sm dark:border-neutral-800">
            <div class="flex items-center gap-2">
              <UIcon name="i-lucide-key-round" class="size-4 text-pink-600" />
              <span class="font-medium">当前 Token</span>
            </div>
            <p class="mt-1 text-xs text-neutral-500">创建于 {{ formatDate(currentToken?.created_at) }}</p>
            <p v-if="!currentURL" class="mt-1 text-xs text-amber-600 dark:text-amber-400">
              旧版本创建的 Token 没有保存明文，无法显示。轮换一次后即可长期查看。
            </p>
          </div>

          <UAlert v-if="issuing" color="neutral" variant="subtle" icon="i-lucide-loader-circle" title="正在生成安全随机 Token…" />

          <UFormField v-if="currentURL" label="Mihomo / YAML 订阅链接">
            <div class="flex gap-2">
              <UInput :model-value="currentURL" readonly class="w-full mono text-xs" />
              <UButton icon="i-lucide-copy" color="neutral" variant="subtle" @click="copyText(currentURL, 'Mihomo 订阅链接已复制')" />
            </div>
          </UFormField>

          <UFormField v-if="currentXrayURL" label="Xray / V2Ray 订阅链接">
            <div class="flex gap-2">
              <UInput :model-value="currentXrayURL" readonly class="w-full mono text-xs" />
              <UButton icon="i-lucide-copy" color="neutral" variant="subtle" @click="copyText(currentXrayURL, 'Xray 订阅链接已复制')" />
            </div>
            <p class="mt-1 text-xs text-neutral-500">返回 Base64 编码的分享链接列表，可直接导入 Xray / V2Ray / v2rayNG 客户端；链式代理、TUIC 和 SSH 不会写入该格式。</p>
          </UFormField>


          <p v-if="tokenProfile" class="text-xs text-neutral-500">
            配置：<span class="font-medium text-neutral-700 dark:text-neutral-300">{{ tokenProfile.name }}</span>
          </p>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full flex-wrap justify-end gap-2">
          <UButton v-if="currentToken" color="error" variant="ghost" icon="i-lucide-shield-off" @click="revokeToken">撤销</UButton>
          <UButton color="neutral" variant="ghost" @click="tokenOpen = false">关闭</UButton>
          <UButton icon="i-lucide-key-round" :loading="issuing" @click="issueToken">
            {{ currentToken ? '轮换链接' : '创建链接' }}
          </UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="deleteOpen" title="删除订阅配置" :ui="{ content: 'max-w-md' }">
      <template #body>
        <div class="space-y-4">
          <p class="text-sm text-neutral-600 dark:text-neutral-300">
            确定删除 <span class="font-medium">{{ deleteTarget?.name }}</span>？其订阅 Token 和链接将立即失效。
          </p>
          <UAlert v-if="deleteError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="deleteError" />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="deleteOpen = false">取消</UButton>
          <UButton color="error" icon="i-lucide-trash-2" :loading="deleting" @click="confirmDelete">删除</UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
