<script setup lang="ts">
import { parse as parseYAML, stringify as stringifyYAML } from 'yaml'
import type { ChainItem, NodeItem, PolicyGroup, PolicyRule, ProfileDetail } from '~/types/api'
import { ApiError } from '~/composables/useApi'

const props = defineProps<{ profileId?: string }>()
const isNew = computed(() => !props.profileId)

const { api, download } = useApi()
const { protocolColor, protocolLabel, hostPort } = useFormat()
const toast = useToast()

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const nodes = ref<NodeItem[]>([])
const chains = ref<ChainItem[]>([])
const name = ref('')
const description = ref('')
const template = ref<'acl4ssr' | 'custom'>('acl4ssr')
const selectedNodes = ref<string[]>([])
const selectedChains = ref<string[]>([])
const defaultExitType = ref<'none' | 'node' | 'chain'>('none')
const defaultExitID = ref('')
const forceDefaultExit = ref(false)
const groups = ref<PolicyGroup[]>([])
const rules = ref<PolicyRule[]>([])
const dnsYaml = ref('')
const generalYaml = ref('')
const nodeSearch = ref('')
const chainSearch = ref('')

const filteredNodes = computed(() => {
  const term = nodeSearch.value.trim().toLowerCase()
  if (!term) return nodes.value
  return nodes.value.filter((n) =>
    n.name.toLowerCase().includes(term) ||
    n.protocol.toLowerCase().includes(term) ||
    n.config.server.toLowerCase().includes(term) ||
    n.tags.some((tag) => tag.toLowerCase().includes(term))
  )
})
const filteredChains = computed(() => {
  const term = chainSearch.value.trim().toLowerCase()
  if (!term) return chains.value
  return chains.value.filter((c) =>
    c.name.toLowerCase().includes(term) ||
    c.entry_node.name.toLowerCase().includes(term) ||
    c.exit_node.name.toLowerCase().includes(term)
  )
})

const ruleTypeItems = [
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'GEOIP', 'GEOSITE', 'RULE-SET',
  'IP-CIDR', 'IP-CIDR6', 'PROCESS-NAME', 'PROCESS-PATH', 'DST-PORT', 'SRC-PORT',
  'NETWORK', 'IN-PORT', 'SRC-IP-CIDR'
].map((value) => ({ label: value, value }))
const templateItems = [
  { label: 'ACL4SSR（推荐）', value: 'acl4ssr' },
  { label: '自定义策略组与规则', value: 'custom' }
]
const defaultTypeItems = [
  { label: '不设置默认出口', value: 'none' },
  { label: '节点', value: 'node' },
  { label: '链式代理', value: 'chain' }
]

const nodeMap = computed(() => new Map(nodes.value.map((n) => [n.id, n])))
const chainMap = computed(() => new Map(chains.value.map((c) => [c.id, c])))
const selectedNodeObjects = computed(() => selectedNodes.value.map((id) => nodeMap.value.get(id)).filter(Boolean) as NodeItem[])
const selectedChainObjects = computed(() => selectedChains.value.map((id) => chainMap.value.get(id)).filter(Boolean) as ChainItem[])

const defaultTargetItems = computed(() => {
  if (defaultExitType.value === 'node') {
    return selectedNodeObjects.value.map((n) => ({ label: `${n.name} · ${protocolLabel(n.protocol)}`, value: n.id }))
  }
  if (defaultExitType.value === 'chain') {
    return selectedChainObjects.value
      .filter((c) => c.enabled)
      .map((c) => ({ label: `${c.name} (${c.entry_node.name} → ${c.exit_node.name})`, value: c.id }))
  }
  return []
})

const proxyOptions = computed(() => {
  const items: Array<{ label: string; value: string }> = []
  for (const node of selectedNodeObjects.value) {
    items.push({ label: `节点 · ${node.name}`, value: `node:${node.id}` })
  }
  for (const chain of selectedChainObjects.value) {
    items.push({ label: `链式代理 · ${chain.name}`, value: `chain:${chain.id}` })
  }
  for (const group of groups.value) {
    items.push({ label: `策略组 · ${group.name}`, value: `group:${group.name}` })
  }
  items.push({ label: 'DIRECT', value: 'DIRECT' })
  items.push({ label: 'REJECT', value: 'REJECT' })
  return items
})

function proxyOptionsFor(group: PolicyGroup) {
  return proxyOptions.value.filter((item) => item.value !== `group:${group.name}`)
}

const ruleTargetOptions = computed(() => {
  const items: Array<{ label: string; value: string }> = []
  for (const group of groups.value) items.push({ label: `策略组 · ${group.name}`, value: `group:${group.name}` })
  for (const node of selectedNodeObjects.value) items.push({ label: `节点 · ${node.name}`, value: `node:${node.id}` })
  for (const chain of selectedChainObjects.value) items.push({ label: `链式代理 · ${chain.name}`, value: `chain:${chain.id}` })
  items.push({ label: 'DIRECT', value: 'DIRECT' })
  items.push({ label: 'REJECT', value: 'REJECT' })
  return items
})

const summaryExit = computed(() => {
  if (defaultExitType.value === 'node') return nodeMap.value.get(defaultExitID.value)?.name || '未选择'
  if (defaultExitType.value === 'chain') return chainMap.value.get(defaultExitID.value)?.name || '未选择'
  return '无（首个策略组）'
})

function parseYAMLObject(text: string, label: string): Record<string, unknown> {
  if (!text.trim()) return {}
  let value: unknown
  try {
    value = parseYAML(text)
  } catch {
    throw new Error(`${label} 不是有效的 YAML。`)
  }
  if (value === null || value === undefined) return {}
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} 必须是 YAML 映射/对象。`)
  return value as Record<string, unknown>
}

function stringifyObject(value: Record<string, unknown> | undefined): string {
  if (!value || Object.keys(value).length === 0) return ''
  return stringifyYAML(value, { lineWidth: 0 }).trimEnd()
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [nodeData, chainData] = await Promise.all([
      api<{ nodes: NodeItem[] }>('/api/nodes'),
      api<{ chains: ChainItem[] }>('/api/chains')
    ])
    nodes.value = nodeData.nodes
    chains.value = chainData.chains

    if (props.profileId) {
      const data = await api<{ profile: ProfileDetail }>(`/api/profiles/${props.profileId}`)
      const profile = data.profile
      name.value = profile.name
      description.value = profile.description
      template.value = profile.template === 'acl4ssr' ? 'acl4ssr' : 'custom'
      selectedNodes.value = [...profile.node_ids]
      selectedChains.value = [...profile.chain_ids]
      defaultExitType.value = profile.default_exit_type || 'none'
      defaultExitID.value = profile.default_exit_id
      forceDefaultExit.value = profile.force_default_exit
      groups.value = (profile.groups || []).map((g) => ({ ...g, proxies: [...g.proxies] }))
      rules.value = (profile.rules || []).map((r) => ({ ...r }))
      dnsYaml.value = stringifyObject(profile.dns)
      generalYaml.value = stringifyObject(profile.general)
    } else {
      template.value = 'acl4ssr'
    }
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '加载订阅配置失败。'
  } finally {
    loading.value = false
  }
}

function pruneReferences() {
  const nodeRefs = new Set(selectedNodes.value.map((id) => `node:${id}`))
  const chainRefs = new Set(selectedChains.value.map((id) => `chain:${id}`))
  for (const group of groups.value) {
    group.proxies = group.proxies.filter((ref) => {
      if (ref.startsWith('node:')) return nodeRefs.has(ref)
      if (ref.startsWith('chain:')) return chainRefs.has(ref)
      return true
    })
  }
  for (const rule of rules.value) {
    if (rule.target.startsWith('node:') && !nodeRefs.has(rule.target)) rule.target = 'DIRECT'
    if (rule.target.startsWith('chain:') && !chainRefs.has(rule.target)) rule.target = 'DIRECT'
  }
  if (defaultExitType.value === 'node' && !selectedNodes.value.includes(defaultExitID.value)) {
    defaultExitType.value = 'none'
    defaultExitID.value = ''
    forceDefaultExit.value = false
  }
  if (defaultExitType.value === 'chain' && !selectedChains.value.includes(defaultExitID.value)) {
    defaultExitType.value = 'none'
    defaultExitID.value = ''
    forceDefaultExit.value = false
  }
}

function toggleNode(id: string, value: boolean | 'indeterminate') {
  if (value === true) {
    if (!selectedNodes.value.includes(id)) selectedNodes.value = [...selectedNodes.value, id]
  } else {
    selectedNodes.value = selectedNodes.value.filter((nodeID) => nodeID !== id)
    const dependentChains = selectedChainObjects.value.filter((c) => c.entry_node.id === id).map((c) => c.id)
    if (dependentChains.length) {
      selectedChains.value = selectedChains.value.filter((chainID) => !dependentChains.includes(chainID))
    }
  }
  pruneReferences()
}

function toggleChain(id: string, value: boolean | 'indeterminate') {
  if (value === true) {
    if (!selectedChains.value.includes(id)) {
      selectedChains.value = [...selectedChains.value, id]
      const chain = chainMap.value.get(id)
      if (chain && !selectedNodes.value.includes(chain.entry_node.id)) {
        selectedNodes.value = [...selectedNodes.value, chain.entry_node.id]
      }
    }
  } else {
    selectedChains.value = selectedChains.value.filter((chainID) => chainID !== id)
  }
  pruneReferences()
}

function selectAllNodes() {
  selectedNodes.value = nodes.value.map((n) => n.id)
  pruneReferences()
}

function clearNodes() {
  selectedNodes.value = []
  selectedChains.value = []
  pruneReferences()
}

function selectAllChains() {
  const chainIDs = new Set(selectedChains.value)
  const nodeIDs = new Set(selectedNodes.value)
  for (const chain of chains.value) {
    if (!chain.enabled) continue
    chainIDs.add(chain.id)
    nodeIDs.add(chain.entry_node.id)
  }
  selectedChains.value = [...chainIDs]
  selectedNodes.value = [...nodeIDs]
  pruneReferences()
}

function onDefaultTypeChange() {
  defaultExitID.value = ''
  if (defaultExitType.value === 'none') forceDefaultExit.value = false
}

function addGroup() {
  let index = groups.value.length + 1
  let groupName = `策略组 ${index}`
  while (groups.value.some((g) => g.name === groupName)) {
    index++
    groupName = `策略组 ${index}`
  }
  groups.value.push({
    name: groupName,
    type: 'select',
    proxies: [...selectedNodes.value.map((id) => `node:${id}`), ...selectedChains.value.map((id) => `chain:${id}`)]
  })
}

function removeGroup(index: number) {
  const [removed] = groups.value.splice(index, 1)
  if (!removed) return
  const ref = `group:${removed.name}`
  for (const group of groups.value) group.proxies = group.proxies.filter((p) => p !== ref)
  for (const rule of rules.value) if (rule.target === ref) rule.target = 'DIRECT'
}

function addRule() {
  rules.value.push({
    type: 'DOMAIN-SUFFIX',
    payload: '',
    target: groups.value.length ? `group:${groups.value[0]!.name}` : 'DIRECT'
  })
}

function removeRule(index: number) {
  rules.value.splice(index, 1)
}

function applyDNSTemplate() {
  dnsYaml.value = [
    'enable: true',
    'ipv6: false',
    'enhanced-mode: fake-ip',
    'fake-ip-range: 198.18.0.1/16',
    'nameserver:',
    '  - https://1.1.1.1/dns-query',
    '  - https://8.8.8.8/dns-query',
    'fallback:',
    '  - tls://1.1.1.1:853'
  ].join('\n')
}

function applyGeneralTemplate() {
  generalYaml.value = [
    'mode: rule',
    'log-level: info',
    'ipv6: true',
    'unified-delay: true',
    'tcp-concurrent: true'
  ].join('\n')
}

async function save() {
  error.value = ''
  if (!name.value.trim()) {
    error.value = '订阅配置名称不能为空。'
    return
  }
  if (!selectedNodes.value.length) {
    error.value = '请至少选择一个节点。'
    return
  }
  if (forceDefaultExit.value && defaultExitType.value === 'none') {
    error.value = '强制默认出口需要先选择一个默认出口。'
    return
  }
  let dns: Record<string, unknown>
  let general: Record<string, unknown>
  try {
    dns = parseYAMLObject(dnsYaml.value, 'DNS 配置')
    general = parseYAMLObject(generalYaml.value, '通用设置')
  } catch (e) {
    error.value = (e as Error).message
    return
  }
  const payload = {
    name: name.value.trim(),
    description: description.value,
    template: template.value === 'acl4ssr' ? 'acl4ssr' : '',
    node_ids: [...selectedNodes.value].sort(),
    chain_ids: [...selectedChains.value].sort(),
    default_exit_type: defaultExitType.value === 'none' ? '' : defaultExitType.value,
    default_exit_id: defaultExitID.value,
    force_default_exit: forceDefaultExit.value,
    groups: groups.value.map((group) => ({
      ...group,
      interval: group.interval === undefined || group.interval === null || String(group.interval) === '' ? undefined : Number(group.interval),
      tolerance: group.tolerance === undefined || group.tolerance === null || String(group.tolerance) === '' ? undefined : Number(group.tolerance),
      lazy: !!group.lazy
    })),
    rules: rules.value,
    dns,
    general
  }
  saving.value = true
  try {
    if (props.profileId) {
      await api(`/api/profiles/${props.profileId}`, { method: 'PUT', body: payload })
      toast.add({ title: '订阅配置已保存', icon: 'i-lucide-check-circle-2' })
    } else {
      await api('/api/profiles', { method: 'POST', body: payload })
      toast.add({ title: '订阅配置已创建', icon: 'i-lucide-check-circle-2' })
    }
    await navigateTo('/profiles')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '保存订阅配置失败。'
  } finally {
    saving.value = false
  }
}

const previewOpen = ref(false)
const previewYaml = ref('')
const previewLoading = ref(false)

async function preview() {
  if (!props.profileId) {
    toast.add({ title: '请先保存订阅配置', description: '预览基于已保存的配置生成。', color: 'warning', icon: 'i-lucide-info' })
    return
  }
  previewOpen.value = true
  previewLoading.value = true
  previewYaml.value = ''
  try {
    const response = await fetch(`/api/profiles/${props.profileId}/preview`, { credentials: 'same-origin' })
    if (!response.ok) {
      let message = '预览失败。'
      try { message = (await response.json())?.error?.message || message } catch { /* ignore */ }
      throw new Error(message)
    }
    previewYaml.value = await response.text()
  } catch (e) {
    toast.add({ title: '预览失败', description: (e as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    previewLoading.value = false
  }
}

function downloadProfile() {
  if (!props.profileId) return
  download(`/api/profiles/${props.profileId}/download`, `${name.value || 'profile'}.yaml`).catch((e) => {
    toast.add({ title: '下载失败', description: (e as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  })
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <div class="flex items-center gap-2">
          <UButton to="/profiles" icon="i-lucide-arrow-left" color="neutral" variant="ghost" size="xs" />
          <h1 class="text-2xl font-semibold tracking-tight">{{ isNew ? '新建订阅配置' : '编辑订阅配置' }}</h1>
        </div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
          可视化选择节点、策略组和规则。高级 DNS 与通用设置通过 YAML 编辑。
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <UButton color="neutral" variant="subtle" icon="i-lucide-eye" :disabled="isNew" @click="preview">预览</UButton>
        <UButton color="neutral" variant="subtle" icon="i-lucide-download" :disabled="isNew" @click="downloadProfile">下载</UButton>
        <UButton icon="i-lucide-save" :loading="saving" @click="save">保存订阅配置</UButton>
      </div>
    </div>

    <div v-if="loading" class="grid gap-6 lg:grid-cols-3">
      <div class="space-y-4 lg:col-span-2">
        <div v-for="i in 4" :key="i" class="h-40 animate-pulse rounded-xl bg-neutral-100 dark:bg-neutral-800" />
      </div>
      <div class="h-64 animate-pulse rounded-xl bg-neutral-100 dark:bg-neutral-800" />
    </div>

    <div v-else class="grid gap-6 lg:grid-cols-3">
      <div class="space-y-6 lg:col-span-2">
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" />

        <UCard>
          <template #header><h2 class="font-semibold">基本信息</h2></template>
          <div class="grid gap-4 sm:grid-cols-2">
            <UFormField label="订阅配置名称" required class="sm:col-span-2">
              <UInput v-model="name" placeholder="日常" class="w-full" />
            </UFormField>
            <UFormField label="描述" class="sm:col-span-2">
              <UTextarea v-model="description" :rows="2" placeholder="这个订阅配置用于什么场景？" class="w-full" />
            </UFormField>
            <UFormField label="规则模板" hint="ACL4SSR 模板会接管策略组和路由规则" class="sm:col-span-2">
              <USelect v-model="template" :items="templateItems" class="w-full" />
            </UFormField>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 class="font-semibold">节点</h2>
                <p class="text-xs text-neutral-500">此配置启用的原始节点。每条链式代理的入口节点为必需项。</p>
              </div>
              <div class="flex gap-1">
                <UButton size="xs" color="neutral" variant="ghost" @click="selectAllNodes">全选</UButton>
                <UButton size="xs" color="neutral" variant="ghost" @click="clearNodes">清空</UButton>
              </div>
            </div>
          </template>
          <UInput v-model="nodeSearch" icon="i-lucide-search" placeholder="搜索节点…" class="mb-3 w-full" />
          <div v-if="!nodes.length" class="py-8 text-center text-sm text-neutral-500">
            暂无可用节点。<NuxtLink to="/nodes" class="text-pink-600 hover:underline">添加节点</NuxtLink>。
          </div>
          <div v-else class="max-h-80 space-y-1 overflow-y-auto pr-1 scroll-thin">
            <label
              v-for="node in filteredNodes"
              :key="node.id"
              class="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-2 hover:bg-neutral-50 dark:hover:bg-neutral-900"
            >
              <UCheckbox :model-value="selectedNodes.includes(node.id)" @update:model-value="(v) => toggleNode(node.id, v)" />
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="truncate text-sm font-medium">{{ node.name }}</span>
                  <UBadge :color="protocolColor(node.protocol)" variant="subtle" size="sm">{{ protocolLabel(node.protocol) }}</UBadge>
                </div>
                <div class="mono text-[11px] text-neutral-500">{{ hostPort(node.config.server, node.config.port) }}</div>
              </div>
              <div class="flex gap-1">
                <UBadge v-for="tag in node.tags.slice(0, 2)" :key="tag" color="neutral" variant="subtle" size="sm">{{ tag }}</UBadge>
              </div>
            </label>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 class="font-semibold">链式代理</h2>
                <p class="text-xs text-neutral-500">每条选中的链式代理都会通过 <span class="mono">dialer-proxy</span> 生成一个额外代理。</p>
              </div>
              <UButton size="xs" color="neutral" variant="ghost" @click="selectAllChains">全选已启用</UButton>
            </div>
          </template>
          <UInput v-model="chainSearch" icon="i-lucide-search" placeholder="搜索链式代理…" class="mb-3 w-full" />
          <div v-if="!chains.length" class="py-8 text-center text-sm text-neutral-500">
            暂无链式代理。<NuxtLink to="/nodes?tab=chains" class="text-pink-600 hover:underline">创建链式代理</NuxtLink>。
          </div>
          <div v-else class="max-h-72 space-y-1 overflow-y-auto pr-1 scroll-thin">
            <label
              v-for="chain in filteredChains"
              :key="chain.id"
              class="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-2 hover:bg-neutral-50 dark:hover:bg-neutral-900"
              :class="chain.enabled ? '' : 'opacity-60'"
            >
              <UCheckbox :model-value="selectedChains.includes(chain.id)" @update:model-value="(v) => toggleChain(chain.id, v)" />
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="truncate text-sm font-medium">{{ chain.name }}</span>
                  <UBadge v-if="!chain.enabled" color="neutral" variant="subtle" size="sm">已禁用</UBadge>
                </div>
                <div class="text-[11px] text-neutral-500">{{ chain.entry_node.name }} → {{ chain.exit_node.name }}</div>
              </div>
            </label>
          </div>
        </UCard>

        <UCard v-if="template === 'acl4ssr'">
          <template #header><h2 class="font-semibold">ACL4SSR 规则模板</h2></template>
          <UAlert
            color="success"
            variant="subtle"
            icon="i-lucide-list-checks"
            title="已启用 ACL4SSR_Online"
            description="策略组与路由规则由内置 ACL4SSR 配置提供，并引用 ACL4SSR 的远程规则集。自定义策略组、规则和默认出口在此模板下不会生效。"
          />
        </UCard>

        <UCard v-if="template === 'custom'">
          <template #header>
            <div class="flex items-center justify-between gap-2">
              <div>
                <h2 class="font-semibold">策略组</h2>
                <p class="text-xs text-neutral-500">支持 select、URL 测试、fallback 和负载均衡。留空将自动生成 Proxy 策略组。</p>
              </div>
              <UButton size="xs" icon="i-lucide-plus" color="neutral" variant="subtle" @click="addGroup">添加策略组</UButton>
            </div>
          </template>
          <div v-if="!groups.length" class="rounded-lg border border-dashed border-neutral-300 p-4 text-center text-sm text-neutral-500 dark:border-neutral-700">
            尚未定义策略组。NyaSub 会生成包含所有已选代理的 <span class="mono">Proxy</span> 选择组。
          </div>
          <div v-else class="space-y-4">
            <PolicyGroupEditor
              v-for="(group, index) in groups"
              :key="index"
              :group="group"
              :index="index"
              :proxy-options="proxyOptionsFor(group)"
              @remove="removeGroup"
            />
          </div>
        </UCard>

        <UCard v-if="template === 'custom'">
          <template #header>
            <div class="flex items-center justify-between gap-2">
              <div>
                <h2 class="font-semibold">路由规则</h2>
                <p class="text-xs text-neutral-500">规则按顺序生成，末尾会自动添加 MATCH 规则。</p>
              </div>
              <UButton size="xs" icon="i-lucide-plus" color="neutral" variant="subtle" @click="addRule">添加规则</UButton>
            </div>
          </template>
          <div v-if="!rules.length" class="rounded-lg border border-dashed border-neutral-300 p-4 text-center text-sm text-neutral-500 dark:border-neutral-700">
            没有自定义规则。流量通过 <span class="mono">MATCH</span> 到达默认出口。
          </div>
          <div v-else class="space-y-3">
            <div v-for="(rule, index) in rules" :key="index" class="grid gap-2 rounded-lg border border-neutral-200 p-3 dark:border-neutral-800 sm:grid-cols-[10rem_1fr_12rem_auto]">
              <USelect v-model="rule.type" :items="ruleTypeItems" class="w-full" />
              <UInput v-model="rule.payload" placeholder="example.com" class="w-full" />
              <USelectMenu v-model="rule.target" :items="ruleTargetOptions" value-key="value" placeholder="目标" class="w-full" />
              <div class="flex items-center gap-1">
                <UCheckbox v-if="['IP-CIDR', 'IP-CIDR6', 'GEOIP'].includes(rule.type)" v-model="rule.no_resolve" label="no-resolve" />
                <UButton icon="i-lucide-x" size="xs" color="error" variant="ghost" aria-label="删除规则" @click="removeRule(index)" />
              </div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">高级设置</h2>
            <p class="text-xs text-neutral-500">DNS 与 Mihomo 通用设置的 YAML 映射。保留字段会被拒绝。</p>
          </template>
          <div class="grid gap-5 lg:grid-cols-2">
            <UFormField label="DNS 配置">
              <div class="mb-2 flex justify-end">
                <UButton size="xs" color="neutral" variant="ghost" @click="applyDNSTemplate">使用模板</UButton>
              </div>
              <UTextarea v-model="dnsYaml" :rows="12" class="w-full mono" placeholder="enable: true&#10;enhanced-mode: fake-ip" />
            </UFormField>
            <UFormField label="通用设置">
              <div class="mb-2 flex justify-end">
                <UButton size="xs" color="neutral" variant="ghost" @click="applyGeneralTemplate">使用模板</UButton>
              </div>
              <UTextarea v-model="generalYaml" :rows="12" class="w-full mono" placeholder="mode: rule&#10;log-level: info" />
            </UFormField>
          </div>
        </UCard>
      </div>

      <div class="space-y-6">
        <UCard v-if="template === 'acl4ssr'" class="lg:sticky lg:top-6">
          <template #header><h2 class="font-semibold">ACL4SSR 模板</h2></template>
          <p class="text-sm text-neutral-500">
            最终出口由 ACL4SSR 的「🐟 漏网之鱼」策略组决定。切换为“自定义策略组与规则”后才能设置默认出口。
          </p>
        </UCard>

        <UCard v-if="template === 'custom'" class="lg:sticky lg:top-6">
          <template #header>
            <h2 class="font-semibold">默认出口</h2>
            <p class="text-xs text-neutral-500">用于最终的 MATCH 规则。</p>
          </template>
          <div class="space-y-4">
            <UFormField label="类型">
              <USelect v-model="defaultExitType" :items="defaultTypeItems" class="w-full" @update:model-value="onDefaultTypeChange" />
            </UFormField>
            <UFormField v-if="defaultExitType !== 'none'" label="目标">
              <USelectMenu v-model="defaultExitID" :items="defaultTargetItems" value-key="value" placeholder="选择目标…" class="w-full" />
            </UFormField>
            <USwitch v-model="forceDefaultExit" label="强制默认出口" :disabled="defaultExitType === 'none'" />
            <p class="text-xs text-neutral-500">
              强制模式会直接写入 <span class="mono">MATCH,&lt;proxy&gt;</span>，而不是可选择策略组，从而在客户端保留旧选择时仍尽量确定出口。客户端处于全局模式时仍可覆盖规则。
            </p>
            <div class="rounded-lg bg-neutral-50 p-3 text-xs dark:bg-neutral-900">
              <div class="text-neutral-500">实际 MATCH 目标</div>
              <div class="mt-1 font-medium">{{ summaryExit }}</div>
            </div>
          </div>
        </UCard>

        <UCard>
          <template #header><h2 class="font-semibold">摘要</h2></template>
          <dl class="space-y-2 text-sm">
            <div class="flex justify-between"><dt class="text-neutral-500">节点</dt><dd class="font-medium">{{ selectedNodes.length }}</dd></div>
            <div class="flex justify-between"><dt class="text-neutral-500">链式代理</dt><dd class="font-medium">{{ selectedChains.length }}</dd></div>
            <div class="flex justify-between"><dt class="text-neutral-500">策略组</dt><dd class="font-medium">{{ template === 'acl4ssr' ? 'ACL4SSR' : (groups.length || '1（自动）') }}</dd></div>
            <div class="flex justify-between"><dt class="text-neutral-500">规则</dt><dd class="font-medium">{{ template === 'acl4ssr' ? 'ACL4SSR' : rules.length }}</dd></div>
            <div class="flex justify-between"><dt class="text-neutral-500">DNS</dt><dd class="font-medium">{{ dnsYaml.trim() ? '自定义' : '默认' }}</dd></div>
          </dl>
          <UAlert
            v-if="forceDefaultExit"
            class="mt-4"
            color="warning"
            variant="subtle"
            icon="i-lucide-pin"
            title="已启用强制出口"
            description="规则仍会优先路由特定流量，请谨慎设置规则目标。"
          />
        </UCard>
      </div>
    </div>

    <UModal v-model:open="previewOpen" title="订阅配置 YAML 预览" :ui="{ content: 'max-w-4xl' }">
      <template #body>
        <div v-if="previewLoading" class="h-64 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
        <pre v-else class="yaml-preview">{{ previewYaml }}</pre>
      </template>
      <template #footer>
        <div class="flex w-full justify-end">
          <UButton color="neutral" variant="ghost" @click="previewOpen = false">关闭</UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
