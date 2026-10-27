<script setup lang="ts">
import type { ChainItem, NodeItem } from '~/types/api'
import { ApiError } from '~/composables/useApi'

const { api } = useApi()
const { protocolLabel, protocolColor, hostPort, timeAgo } = useFormat()
const toast = useToast()

const chains = ref<ChainItem[]>([])
const nodes = ref<NodeItem[]>([])
const loading = ref(true)

const nodeOptions = computed(() => nodes.value.map((node) => ({
  label: `${node.name} · ${protocolLabel(node.protocol)} · ${hostPort(node.config.server, node.config.port)}`,
  value: node.id,
  protocol: node.protocol,
  name: node.name,
  server: node.config.server,
  port: node.config.port
})))

async function load() {
  loading.value = true
  try {
    const [chainData, nodeData] = await Promise.all([
      api<{ chains: ChainItem[] }>('/api/chains'),
      api<{ nodes: NodeItem[] }>('/api/nodes')
    ])
    chains.value = chainData.chains
    nodes.value = nodeData.nodes
  } catch (error) {
    toast.add({ title: '加载链式代理失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    loading.value = false
  }
}

const formOpen = ref(false)
const editID = ref<string | null>(null)
const form = reactive({
  name: '',
  entry: '',
  exit: '',
  enabled: true
})
const saving = ref(false)
const formError = ref('')
const formWarnings = ref<string[]>([])

const entryOption = computed(() => nodeOptions.value.find((o) => o.value === form.entry))
const exitOption = computed(() => nodeOptions.value.find((o) => o.value === form.exit))

function openCreate() {
  editID.value = null
  form.name = ''
  form.entry = ''
  form.exit = ''
  form.enabled = true
  formError.value = ''
  formWarnings.value = []
  formOpen.value = true
}

function openEdit(chain: ChainItem) {
  editID.value = chain.id
  form.name = chain.name
  form.entry = chain.entry_node.id
  form.exit = chain.exit_node.id
  form.enabled = chain.enabled
  formError.value = ''
  formWarnings.value = [...(chain.warnings || [])]
  formOpen.value = true
}

function copyChain(chain: ChainItem) {
  editID.value = null
  form.name = `${chain.name}（副本）`
  form.entry = chain.entry_node.id
  form.exit = chain.exit_node.id
  form.enabled = chain.enabled
  formError.value = ''
  formWarnings.value = [...(chain.warnings || [])]
  formOpen.value = true
}

async function saveChain() {
  formError.value = ''
  if (!form.name.trim()) {
    formError.value = '名称不能为空。'
    return
  }
  if (!form.entry || !form.exit) {
    formError.value = '请同时选择入口和出口节点。'
    return
  }
  if (form.entry === form.exit) {
    formError.value = '入口和出口节点不能相同。'
    return
  }
  saving.value = true
  try {
    const body = {
      name: form.name.trim(),
      entry_node_id: form.entry,
      exit_node_id: form.exit,
      enabled: form.enabled
    }
    if (editID.value) {
      await api(`/api/chains/${editID.value}`, { method: 'PUT', body })
      toast.add({ title: '链式代理已更新', icon: 'i-lucide-check-circle-2' })
    } else {
      await api('/api/chains', { method: 'POST', body })
      toast.add({ title: '链式代理已创建', icon: 'i-lucide-link-2' })
    }
    formOpen.value = false
    await load()
  } catch (error) {
    formError.value = error instanceof ApiError ? error.message : '保存链式代理失败。'
  } finally {
    saving.value = false
  }
}

async function toggleChain(chain: ChainItem, enabled: boolean) {
  try {
    await api(`/api/chains/${chain.id}`, {
      method: 'PUT',
      body: {
        name: chain.name,
        entry_node_id: chain.entry_node.id,
        exit_node_id: chain.exit_node.id,
        enabled
      }
    })
    chain.enabled = enabled
    toast.add({ title: enabled ? '链式代理已启用' : '链式代理已禁用', icon: enabled ? 'i-lucide-toggle-right' : 'i-lucide-toggle-left' })
  } catch (error) {
    const apiError = error instanceof ApiError ? error : null
    toast.add({ title: '无法更改链式代理状态', description: apiError?.message || '更新失败。', color: 'error', icon: 'i-lucide-triangle-alert' })
    await load()
  }
}

const deleteOpen = ref(false)
const deleteTarget = ref<ChainItem | null>(null)
const deleteForce = ref(false)
const deleteError = ref('')
const deleting = ref(false)

function askDelete(chain: ChainItem) {
  deleteTarget.value = chain
  deleteForce.value = false
  deleteError.value = ''
  deleteOpen.value = true
}

async function confirmDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  deleteError.value = ''
  try {
    await api(`/api/chains/${deleteTarget.value.id}?force=${deleteForce.value}`, { method: 'DELETE' })
    toast.add({ title: '链式代理已删除', icon: 'i-lucide-trash-2' })
    deleteOpen.value = false
    await load()
  } catch (error) {
    const apiError = error instanceof ApiError ? error : null
    deleteError.value = apiError?.message || '删除失败。'
    if (apiError?.code === 'chain_in_use') {
      deleteError.value += ' 请先更新引用该链式代理的订阅配置，或使用强制删除移除相关选择。'
    }
  } finally {
    deleting.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">链式代理</h1>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
          使用 Mihomo <span class="mono text-xs">dialer-proxy</span> 将入口节点与出口节点串联。
        </p>
      </div>
      <UButton icon="i-lucide-plus" @click="openCreate">新建链式代理</UButton>
    </div>

    <UAlert
      v-if="!nodes.length && !loading"
      class="mb-4"
      color="warning"
      variant="subtle"
      icon="i-lucide-info"
      title="请先添加节点"
      description="链式代理需要两个已有节点。请前往节点页面导入或创建节点。"
    />

    <div v-if="loading" class="grid gap-4 md:grid-cols-2">
      <div v-for="i in 4" :key="i" class="h-36 animate-pulse rounded-xl bg-neutral-100 dark:bg-neutral-800" />
    </div>
    <div v-else-if="!chains.length" class="rounded-xl border border-dashed border-neutral-300 py-16 text-center dark:border-neutral-700">
      <UIcon name="i-lucide-link-2-off" class="mx-auto size-10 text-neutral-300 dark:text-neutral-700" />
      <h2 class="mt-3 font-medium">还没有链式代理</h2>
      <p class="mt-1 text-sm text-neutral-500">创建第一条入口 → 出口链路。</p>
      <UButton class="mt-4" icon="i-lucide-plus" :disabled="nodes.length < 2" @click="openCreate">新建链式代理</UButton>
    </div>
    <div v-else class="grid gap-4 md:grid-cols-2">
      <UCard v-for="chain in chains" :key="chain.id" :class="chain.enabled ? '' : 'opacity-70'">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <h2 class="truncate font-semibold">{{ chain.name }}</h2>
              <UBadge :color="chain.enabled ? 'success' : 'neutral'" variant="subtle" size="sm">
                {{ chain.enabled ? '已启用' : '已禁用' }}
              </UBadge>
            </div>
            <p class="mt-0.5 text-xs text-neutral-500">被 {{ chain.profile_count }} 个订阅配置使用</p>
          </div>
          <USwitch :model-value="chain.enabled" aria-label="切换链式代理状态" @update:model-value="(v) => toggleChain(chain, v === true)" />
        </div>

        <div class="mt-4 flex flex-wrap items-center gap-2 text-sm">
          <span class="rounded-md bg-neutral-100 px-2 py-1 text-xs text-neutral-500 dark:bg-neutral-800">客户端</span>
          <UIcon name="i-lucide-arrow-right" class="size-3.5 text-neutral-400" />
          <div class="flex min-w-0 items-center gap-1.5 rounded-md border border-neutral-200 bg-white px-2 py-1 dark:border-neutral-700 dark:bg-neutral-900">
            <UBadge :color="protocolColor(chain.entry_node.protocol)" variant="subtle" size="sm">{{ protocolLabel(chain.entry_node.protocol) }}</UBadge>
            <span class="max-w-32 truncate font-medium">{{ chain.entry_node.name }}</span>
          </div>
          <UIcon name="i-lucide-arrow-right" class="size-3.5 text-neutral-400" />
          <div class="flex min-w-0 items-center gap-1.5 rounded-md border border-neutral-200 bg-white px-2 py-1 dark:border-neutral-700 dark:bg-neutral-900">
            <UBadge :color="protocolColor(chain.exit_node.protocol)" variant="subtle" size="sm">{{ protocolLabel(chain.exit_node.protocol) }}</UBadge>
            <span class="max-w-32 truncate font-medium">{{ chain.exit_node.name }}</span>
          </div>
          <UIcon name="i-lucide-arrow-right" class="size-3.5 text-neutral-400" />
          <span class="rounded-md bg-neutral-100 px-2 py-1 text-xs text-neutral-500 dark:bg-neutral-800">互联网</span>
        </div>

        <p class="mt-3 text-xs text-neutral-500">
          {{ hostPort(chain.entry_node.server, chain.entry_node.port) }} → {{ hostPort(chain.exit_node.server, chain.exit_node.port) }}
        </p>

        <div v-if="chain.warnings?.length" class="mt-3 space-y-1">
          <UAlert
            v-for="(warning, index) in chain.warnings"
            :key="index"
            color="warning"
            variant="subtle"
            icon="i-lucide-triangle-alert"
            :title="warning"
          />
        </div>

        <div class="mt-4 flex items-center justify-between border-t border-neutral-100 pt-3 dark:border-neutral-900">
          <span class="text-xs text-neutral-400">{{ timeAgo(chain.updated_at) }}</span>
          <div class="flex gap-1">
            <UButton icon="i-lucide-pencil" size="xs" color="neutral" variant="ghost" @click="openEdit(chain)">编辑</UButton>
            <UButton icon="i-lucide-copy" size="xs" color="neutral" variant="ghost" @click="copyChain(chain)">复制</UButton>
            <UButton icon="i-lucide-trash-2" size="xs" color="error" variant="ghost" @click="askDelete(chain)">删除</UButton>
          </div>
        </div>
      </UCard>
    </div>

    <UModal v-model:open="formOpen" :title="editID ? '编辑链式代理' : '新建链式代理'" description="流量路径：客户端 → 入口 → 出口 → 互联网。" :ui="{ content: 'max-w-2xl' }">
      <template #body>
        <form class="space-y-5" @submit.prevent="saveChain">
          <UAlert v-if="formError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="formError" />
          <UFormField label="链式代理名称" required>
            <UInput v-model="form.name" placeholder="HK → US" class="w-full" />
          </UFormField>
          <div class="grid gap-4 sm:grid-cols-2">
            <UFormField label="入口节点" required>
              <USelectMenu v-model="form.entry" :items="nodeOptions" value-key="value" placeholder="搜索入口节点…" class="w-full" />
            </UFormField>
            <UFormField label="出口节点" required>
              <USelectMenu v-model="form.exit" :items="nodeOptions" value-key="value" placeholder="搜索出口节点…" class="w-full" />
            </UFormField>
          </div>

          <div class="rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-900/50">
            <div class="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">链路预览</div>
            <div class="flex flex-wrap items-center gap-2 text-sm">
              <span class="rounded-md bg-white px-2 py-1 text-xs text-neutral-500 shadow-sm dark:bg-neutral-950">客户端</span>
              <UIcon name="i-lucide-arrow-right" class="size-4 text-neutral-400" />
              <div class="rounded-md bg-white px-2 py-1 shadow-sm dark:bg-neutral-950">
                <span class="font-medium">{{ entryOption?.name || '入口' }}</span>
                <span v-if="entryOption" class="ml-1 text-xs text-neutral-500">{{ protocolLabel(entryOption.protocol) }}</span>
              </div>
              <UIcon name="i-lucide-arrow-right" class="size-4 text-neutral-400" />
              <div class="rounded-md bg-white px-2 py-1 shadow-sm dark:bg-neutral-950">
                <span class="font-medium">{{ exitOption?.name || '出口' }}</span>
                <span v-if="exitOption" class="ml-1 text-xs text-neutral-500">{{ protocolLabel(exitOption.protocol) }}</span>
              </div>
              <UIcon name="i-lucide-arrow-right" class="size-4 text-neutral-400" />
              <span class="rounded-md bg-white px-2 py-1 text-xs text-neutral-500 shadow-sm dark:bg-neutral-950">互联网</span>
            </div>
            <p v-if="entryOption && exitOption" class="mt-3 mono text-xs text-neutral-500">
              dialer-proxy: {{ entryOption.name }}
            </p>
          </div>

          <div v-if="formWarnings.length" class="space-y-2">
            <UAlert v-for="(warning, index) in formWarnings" :key="index" color="warning" variant="subtle" icon="i-lucide-triangle-alert" :title="warning" />
          </div>

          <USwitch v-model="form.enabled" label="启用此链式代理" />
        </form>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="formOpen = false">取消</UButton>
          <UButton icon="i-lucide-save" :loading="saving" @click="saveChain">保存链式代理</UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="deleteOpen" title="删除链式代理" :ui="{ content: 'max-w-md' }">
      <template #body>
        <div class="space-y-4">
          <p class="text-sm text-neutral-600 dark:text-neutral-300">
            确定删除 <span class="font-medium">{{ deleteTarget?.name }}</span>？
            需要先修改引用它的订阅默认出口、策略组或规则。
          </p>
          <UAlert v-if="deleteError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="deleteError" />
          <UCheckbox v-model="deleteForce" label="从仅选择了此链的订阅配置中强制移除" />
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
