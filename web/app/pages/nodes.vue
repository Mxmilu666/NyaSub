<script setup lang="ts">
import type { NodeConfig, NodeItem, Protocol } from '~/types/api'
import { ApiError } from '~/composables/useApi'
import { countryOptions, displayName } from '~/utils/country'

const { api, download } = useApi()
const { protocolLabel, protocolColor, formatDate, hostPort } = useFormat()
const toast = useToast()
const route = useRoute()
const router = useRouter()
const activeTab = ref<'nodes' | 'chains'>(route.query.tab === 'chains' ? 'chains' : 'nodes')
useHead({ title: computed(() => activeTab.value === 'chains' ? '链式代理' : '节点') })
const tabItems = [
  { label: '节点', value: 'nodes', icon: 'i-lucide-server' },
  { label: '链式代理', value: 'chains', icon: 'i-lucide-link-2' }
] as const
watch(() => route.query.tab, (value) => {
  activeTab.value = value === 'chains' ? 'chains' : 'nodes'
})
function selectTab(value: string | number) {
  const tab = value === 'chains' ? 'chains' : 'nodes'
  activeTab.value = tab
  router.replace({ query: { ...route.query, tab: tab === 'chains' ? 'chains' : undefined } })
}

const nodes = ref<NodeItem[]>([])
const loading = ref(true)
const search = ref('')
const protocolFilter = ref<'all' | Protocol>('all')
const tagFilter = ref('all')
const tagNames = ref<string[]>([])
const selected = ref<string[]>([])
const tagManagerOpen = ref(false)
const tagManagerLoading = ref(false)
const tagCounts = ref<Array<{ name: string; count: number }>>([])
const tagDeleteOpen = ref(false)
const tagDeleteTarget = ref('')
const tagDeleteError = ref('')
const deletingTag = ref(false)

const filtered = computed(() => {
  const term = search.value.trim().toLowerCase()
  return nodes.value.filter((node) => {
    if (protocolFilter.value !== 'all' && node.protocol !== protocolFilter.value) return false
    if (tagFilter.value !== 'all' && !node.tags.includes(tagFilter.value)) return false
    if (!term) return true
    return (
      node.name.toLowerCase().includes(term) ||
      node.config.server.toLowerCase().includes(term) ||
      node.protocol.toLowerCase().includes(term) ||
      node.tags.some((tag) => tag.toLowerCase().includes(term))
    )
  })
})

const allSelected = computed(() => filtered.value.length > 0 && filtered.value.every((n) => selected.value.includes(n.id)))
const protocolItems = [
  { label: '全部协议', value: 'all' },
  { label: 'VLESS', value: 'vless' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'Shadowsocks', value: 'ss' },
  { label: 'Hysteria2', value: 'hysteria2' },
  { label: 'TUIC', value: 'tuic' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP', value: 'http' },
  { label: 'SSH', value: 'ssh' }
]
const tagItems = computed(() => [{ label: '全部标签', value: 'all' }, ...tagNames.value.map((tag) => ({ label: tag, value: tag }))])
const protocolFormItems = protocolItems.slice(1)

async function load() {
  loading.value = true
  try {
    const data = await api<{ nodes: NodeItem[]; tags: string[] }>('/api/nodes')
    nodes.value = data.nodes
    tagNames.value = data.tags
    selected.value = selected.value.filter((id) => nodes.value.some((n) => n.id === id))
    if (tagFilter.value !== 'all' && !tagNames.value.includes(tagFilter.value)) tagFilter.value = 'all'
  } catch (error) {
    toast.add({ title: '加载节点失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    loading.value = false
  }
}

async function loadTagCounts() {
  tagManagerLoading.value = true
  try {
    const data = await api<{ tags: Array<{ name: string; count: number }> }>('/api/nodes/tags')
    tagCounts.value = data.tags
  } catch (error) {
    toast.add({ title: '加载标签失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    tagManagerLoading.value = false
  }
}

async function openTagManager() {
  tagManagerOpen.value = true
  await loadTagCounts()
}

function askDeleteTag(tag: string) {
  tagDeleteTarget.value = tag
  tagDeleteError.value = ''
  tagDeleteOpen.value = true
}

async function confirmDeleteTag() {
  if (!tagDeleteTarget.value) return
  deletingTag.value = true
  tagDeleteError.value = ''
  try {
    await api(`/api/nodes/tags?tag=${encodeURIComponent(tagDeleteTarget.value)}`, { method: 'DELETE' })
    toast.add({ title: `已删除标签“${tagDeleteTarget.value}”`, icon: 'i-lucide-tag' })
    if (tagFilter.value === tagDeleteTarget.value) tagFilter.value = 'all'
    tagDeleteOpen.value = false
    await Promise.all([load(), loadTagCounts()])
  } catch (error) {
    tagDeleteError.value = error instanceof ApiError ? error.message : '删除标签失败。'
  } finally {
    deletingTag.value = false
  }
}

function toggleAll(value: boolean | 'indeterminate') {
  if (value === true) selected.value = filtered.value.map((n) => n.id)
  else selected.value = []
}

function toggleOne(id: string, value: boolean | 'indeterminate') {
  if (value === true) {
    if (!selected.value.includes(id)) selected.value = [...selected.value, id]
  } else {
    selected.value = selected.value.filter((x) => x !== id)
  }
}

// --- node editor ---------------------------------------------------------
const formOpen = ref(false)
const editID = ref<string | null>(null)
const saving = ref(false)
const formError = ref('')
const form = reactive({
  name: '',
  protocol: 'vless' as Protocol,
  tags: [] as string[],
  country: 'auto',
  port: '443',
  alpn: '',
  extra: '',
  pluginOpts: '',
  hostKeys: '',
  hostKeyAlgorithms: '',
  config: { server: '', port: 443 } as NodeConfig
})
let suppressProtocolWatch = false

const LANDING_TAG = '落地机'
const formTagOptions = computed(() => [...new Set([LANDING_TAG, ...tagNames.value, ...form.tags])].map((tag) => ({ label: tag, value: tag })))

function addFormTag(value: string) {
  const tag = value.trim()
  if (!tag) return
  if ([...tag].length > 32) {
    formError.value = '标签最多 32 个字符。'
    return
  }
  if (form.tags.length >= 16) {
    formError.value = '每个节点最多 16 个标签。'
    return
  }
  if (!form.tags.some((existing) => existing.toLowerCase() === tag.toLowerCase())) {
    form.tags = [...form.tags, tag]
  }
}

const networkItems = [
  { label: 'TCP', value: 'tcp' },
  { label: 'WebSocket', value: 'ws' },
  { label: 'gRPC', value: 'grpc' },
  { label: 'HTTP', value: 'http' },
  { label: 'HTTP/2', value: 'h2' }
]
const tcpOnlyNetworks = [
  { label: 'TCP', value: 'tcp' },
  { label: 'WebSocket', value: 'ws' },
  { label: 'gRPC', value: 'grpc' }
]

function blankConfig(protocol: Protocol, server = '', port = 443): NodeConfig {
  const base: NodeConfig = { server, port }
  if (protocol === 'vless' || protocol === 'vmess') return { ...base, uuid: '', network: 'tcp', tls: false }
  if (protocol === 'trojan') return { ...base, password: '', network: 'tcp' }
  if (protocol === 'ss') return { ...base, cipher: 'aes-256-gcm', password: '' }
  if (protocol === 'hysteria2') return { ...base, password: '', tls: true }
  if (protocol === 'tuic') return { ...base, uuid: '', password: '', tls: true }
  if (protocol === 'ssh') return { ...base, username: '', password: '', private_key: '' }
  return { ...base, tls: false }
}

function cloneConfig(config: NodeConfig): NodeConfig {
  return JSON.parse(JSON.stringify(config)) as NodeConfig
}

function openCreate() {
  editID.value = null
  suppressProtocolWatch = true
  form.name = ''
  form.protocol = 'vless'
  form.tags = []
  form.country = 'auto'
  form.port = '443'
  form.alpn = ''
  form.extra = ''
  form.pluginOpts = ''
  form.hostKeys = ''
  form.hostKeyAlgorithms = ''
  form.config = blankConfig('vless')
  ensureEditorObjects()
  formError.value = ''
  formOpen.value = true
  nextTick(() => { suppressProtocolWatch = false })
}

function openEdit(node: NodeItem) {
  editID.value = node.id
  suppressProtocolWatch = true
  form.name = node.name
  form.protocol = node.protocol
  form.tags = [...node.tags]
  form.country = node.country || 'auto'
  form.port = String(node.config.port)
  form.alpn = (node.config.alpn || []).join(', ')
  form.extra = node.config.extra && Object.keys(node.config.extra).length ? JSON.stringify(node.config.extra, null, 2) : ''
  form.pluginOpts = node.config.plugin_opts && Object.keys(node.config.plugin_opts).length ? JSON.stringify(node.config.plugin_opts, null, 2) : ''
  form.hostKeys = (node.config.host_key || []).join('\n')
  form.hostKeyAlgorithms = (node.config.host_key_algorithms || []).join(', ')
  form.config = cloneConfig(node.config)
  if (form.config.ws && !form.config.ws.headers) form.config.ws.headers = {}
  if (form.config.reality) form.config.reality = { ...form.config.reality }
  ensureEditorObjects()
  formError.value = ''
  formOpen.value = true
  nextTick(() => { suppressProtocolWatch = false })
}

watch(() => form.protocol, (protocol, previous) => {
  if (suppressProtocolWatch || !previous || protocol === previous) return
  const server = form.config.server
  const port = Number(form.port) || 443
  form.config = blankConfig(protocol, server, port)
  ensureEditorObjects()
  form.alpn = ''
  form.extra = ''
  form.pluginOpts = ''
  form.hostKeys = ''
  form.hostKeyAlgorithms = ''
})

const showTransport = computed(() => ['vless', 'vmess', 'trojan'].includes(form.protocol))
const showTLS = computed(() => ['vless', 'vmess', 'socks5', 'http'].includes(form.protocol))
const showSNI = computed(() => showTLS.value || ['trojan', 'hysteria2', 'tuic'].includes(form.protocol))
const showReality = computed(() => form.protocol === 'vless')
const showPortField = computed(() => true)

function ensureEditorObjects() {
  if (form.protocol === 'vless') {
    if (!form.config.reality) form.config.reality = { public_key: '', short_id: '' }
    if (!form.config.reality.public_key) form.config.reality.public_key = ''
    if (!form.config.reality.short_id) form.config.reality.short_id = ''
  }
  if (form.config.network === 'ws') {
    if (!form.config.ws) form.config.ws = { path: '/' }
    if (!form.config.ws.headers) form.config.ws.headers = {}
    if (form.config.ws.headers.Host === undefined) form.config.ws.headers.Host = ''
    if (!form.config.ws.path) form.config.ws.path = '/'
  }
  if (form.config.network === 'grpc') {
    if (!form.config.grpc) form.config.grpc = { service_name: '' }
    if (!form.config.grpc.service_name) form.config.grpc.service_name = ''
  }
  form.config.tls = !!form.config.tls
  form.config.skip_cert_verify = !!form.config.skip_cert_verify
  form.config.udp = !!form.config.udp
  form.config.udp_over_tcp = !!form.config.udp_over_tcp
  form.config.reduce_rtt = !!form.config.reduce_rtt
  form.config.disable_sni = !!form.config.disable_sni
}

watch(() => form.config.network, () => {
  ensureEditorObjects()
})

function cleanObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(cleanObject).filter((v) => v !== undefined && v !== '')
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      const cleaned = cleanObject(val)
      if (cleaned === undefined || cleaned === '') continue
      if (typeof cleaned === 'object' && cleaned !== null && !Array.isArray(cleaned) && Object.keys(cleaned as Record<string, unknown>).length === 0) continue
      out[key] = cleaned
    }
    return out
  }
  return value
}

function buildConfig(): NodeConfig {
  const config = cloneConfig(form.config)
  config.server = form.config.server.trim()
  config.port = Number(form.port)
  if (form.protocol === 'vmess') config.alter_id = Number(config.alter_id || 0)
  if (!config.server) throw new Error('服务器地址不能为空。')
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) throw new Error('端口必须在 1–65535 之间。')
  config.alpn = form.alpn.split(',').map((a) => a.trim()).filter(Boolean)
  if (config.alpn.length === 0) delete config.alpn

  if (form.extra.trim()) {
    try {
      const parsed = JSON.parse(form.extra)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('高级附加字段必须是 JSON 对象。')
      config.extra = parsed as Record<string, unknown>
    } catch (error) {
      throw new Error(`高级附加字段：${(error as Error).message}`)
    }
  } else {
    delete config.extra
  }

  if (form.protocol === 'ss') {
    if (form.config.udp_over_tcp) {
      config.udp_over_tcp = true
      const version = Number(form.config.udp_over_tcp_version)
      if (version === 1 || version === 2) config.udp_over_tcp_version = version
      else delete config.udp_over_tcp_version
    } else {
      delete config.udp_over_tcp
      delete config.udp_over_tcp_version
    }
    if (form.pluginOpts.trim()) {
      try {
        const parsed = JSON.parse(form.pluginOpts)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('插件参数必须是 JSON 对象。')
        config.plugin_opts = parsed as Record<string, unknown>
      } catch (error) {
        throw new Error(`插件参数：${(error as Error).message}`)
      }
    } else {
      delete config.plugin_opts
    }
  } else {
    delete config.plugin_opts
    delete config.udp_over_tcp
    delete config.udp_over_tcp_version
  }

  if (config.reality && !config.reality.public_key) delete config.reality
  if (config.reality) {
    config.tls = true
    if (!config.reality.short_id) delete config.reality.short_id
  }
  if (!showTransport.value) {
    delete config.network
    delete config.ws
    delete config.grpc
    delete config.http_opts
    delete config.h2_opts
  } else {
    if (config.network !== 'ws') delete config.ws
    if (config.network !== 'grpc') delete config.grpc
    if (config.network !== 'http') delete config.http_opts
    if (config.network !== 'h2') delete config.h2_opts
    if (config.network === 'ws') {
      if (!config.ws) config.ws = { path: '/' }
      if (config.ws.headers && Object.keys(config.ws.headers).length === 0) delete config.ws.headers
      if (!config.ws.path) config.ws.path = '/'
      if (config.ws.headers) {
        for (const key of Object.keys(config.ws.headers)) {
          if (!config.ws.headers[key] || !key) delete config.ws.headers[key]
        }
      }
    }
    if (config.network === 'grpc') {
      if (!config.grpc) config.grpc = {}
      if (!config.grpc.service_name) delete config.grpc
    }
  }
  if (form.protocol === 'trojan' || form.protocol === 'hysteria2' || form.protocol === 'tuic' || form.protocol === 'ssh') delete config.tls
  if (form.protocol !== 'ss') delete config.plugin
  if (!['vless', 'vmess', 'trojan', 'ss', 'socks5'].includes(form.protocol)) delete config.udp
  if (form.protocol !== 'hysteria2') {
    delete config.obfs
    delete config.obfs_password
    delete config.up
    delete config.down
    delete config.ports
    delete config.hop_interval
  }
  if (form.protocol !== 'tuic') {
    delete config.congestion_controller
    delete config.udp_relay_mode
    delete config.reduce_rtt
    delete config.disable_sni
  }
  if (form.protocol !== 'vless') {
    delete config.flow
    delete config.encryption
  }
  if (form.protocol !== 'vmess') {
    delete config.alter_id
  }
  if (form.protocol !== 'vmess' && form.protocol !== 'ss') {
    delete config.cipher
  }
  if (form.protocol === 'ss' || form.protocol === 'hysteria2' || form.protocol === 'tuic' || form.protocol === 'socks5' || form.protocol === 'http') {
    delete config.uuid
    delete config.flow
  }
  if (form.protocol === 'trojan' || form.protocol === 'ss' || form.protocol === 'hysteria2') delete config.uuid
  if (form.protocol === 'socks5' || form.protocol === 'http' || form.protocol === 'ssh') {
    // username/password are valid; keep them
  } else {
    delete config.username
  }
  if (['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'tuic'].includes(form.protocol) && form.protocol !== 'tuic') {
    // tuic also has a password, handled below
  }
  if (form.protocol !== 'tuic' && form.protocol !== 'hysteria2' && form.protocol !== 'trojan' && form.protocol !== 'ss' && form.protocol !== 'socks5' && form.protocol !== 'http' && form.protocol !== 'ssh') {
    delete config.password
  }
  if (form.protocol === 'ssh') {
    config.private_key = form.config.private_key?.trim() || undefined
    config.private_key_passphrase = form.config.private_key_passphrase?.trim() || undefined
    const hostKeys = form.hostKeys.split('\n').map((value) => value.trim()).filter(Boolean)
    const algorithms = form.hostKeyAlgorithms.split(',').map((value) => value.trim()).filter(Boolean)
    if (hostKeys.length) config.host_key = hostKeys
    else delete config.host_key
    if (algorithms.length) config.host_key_algorithms = algorithms
    else delete config.host_key_algorithms
  } else {
    delete config.private_key
    delete config.private_key_passphrase
    delete config.host_key
    delete config.host_key_algorithms
  }
  const cleaned = cleanObject(config) as NodeConfig
  cleaned.server = config.server
  cleaned.port = config.port
  return cleaned
}

async function saveNode() {
  formError.value = ''
  if (!form.name.trim()) {
    formError.value = '名称不能为空。'
    return
  }
  let config: NodeConfig
  try {
    config = buildConfig()
  } catch (error) {
    formError.value = (error as Error).message
    return
  }
  const payload = {
    name: form.name.trim(),
    country: form.country === 'auto' ? '' : form.country,
    protocol: form.protocol,
    tags: form.tags,
    config
  }
  saving.value = true
  try {
    if (editID.value) {
      await api(`/api/nodes/${editID.value}`, { method: 'PUT', body: payload })
      toast.add({ title: '节点已更新', icon: 'i-lucide-check-circle-2' })
    } else {
      await api('/api/nodes', { method: 'POST', body: payload })
      toast.add({ title: '节点已创建', icon: 'i-lucide-check-circle-2' })
    }
    formOpen.value = false
    await load()
  } catch (error) {
    formError.value = error instanceof ApiError ? error.message : '保存节点失败。'
  } finally {
    saving.value = false
  }
}

async function copyNode(node: NodeItem) {
  try {
    await api('/api/nodes', {
      method: 'POST',
      body: {
        name: `${node.name}（副本）`,
        country: node.country || '',
        protocol: node.protocol,
        tags: [...node.tags],
        config: node.config
      }
    })
    toast.add({ title: '节点已复制', icon: 'i-lucide-copy-check' })
    await load()
  } catch (error) {
    toast.add({ title: '复制失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  }
}

// --- delete ---------------------------------------------------------------
const deleteOpen = ref(false)
const deleteTargets = ref<string[]>([])
const deleteForce = ref(false)
const deleteError = ref('')
const deleting = ref(false)

function askDelete(ids: string[]) {
  deleteTargets.value = ids
  deleteForce.value = false
  deleteError.value = ''
  deleteOpen.value = true
}

async function confirmDelete() {
  deleting.value = true
  deleteError.value = ''
  try {
    if (deleteTargets.value.length === 1) {
      await api(`/api/nodes/${deleteTargets.value[0]}?force=${deleteForce.value}`, { method: 'DELETE' })
    } else {
      const result = await api<{ deleted: string[]; errors: Array<{ id: string; code: string; message: string }> }>('/api/nodes/bulk-delete', {
        method: 'POST',
        body: { ids: deleteTargets.value, force: deleteForce.value }
      })
      if (result.errors.length) {
        deleteError.value = `已删除 ${result.deleted.length} 个，失败 ${result.errors.length} 个：${result.errors.map((e) => e.message).join(' · ')}`
        await load()
        return
      }
    }
    toast.add({ title: `已删除 ${deleteTargets.value.length} 个节点`, icon: 'i-lucide-trash-2' })
    deleteOpen.value = false
    selected.value = []
    await load()
  } catch (error) {
    const apiError = error instanceof ApiError ? error : null
    deleteError.value = apiError?.message || '删除失败。'
    if (apiError?.code === 'node_in_use') {
      deleteError.value += ' 可勾选强制从订阅配置中移除，或先删除引用该节点的链式代理。'
    }
  } finally {
    deleting.value = false
  }
}

// --- import ---------------------------------------------------------------
const importOpen = ref(false)
const importSource = ref<'content' | 'url'>('content')
const importContent = ref('')
const importURL = ref('')
const importFormat = ref('auto')
const importTags = ref('')
const importPreview = ref<{
  items: Array<{ name: string; protocol: string; duplicate: boolean; existing_name?: string; warnings?: string[] }>
  issues: Array<{ line: number; message: string }>
  duplicate_count: number
} | null>(null)
const importLoading = ref(false)
const importError = ref('')
const importFormatItems = [
  { label: '自动识别', value: 'auto' },
  { label: '分享链接（URI）', value: 'uri' },
  { label: 'Mihomo YAML', value: 'yaml' }
]
const importSourceItems = [
  { label: '粘贴内容', value: 'content' },
  { label: '订阅链接', value: 'url' }
]
const importReady = computed(() => importSource.value === 'url'
  ? importURL.value.trim().length > 0
  : importContent.value.trim().length > 0)

function importPayload(): Record<string, unknown> {
  const tags = importTags.value.split(',').map((t) => t.trim()).filter(Boolean)
  if (importSource.value === 'url') {
    return { url: importURL.value.trim(), tags }
  }
  return { content: importContent.value, format: importFormat.value, tags }
}

watch([importSource, importURL, importContent, importFormat], () => {
  importPreview.value = null
  importError.value = ''
})

function openImport() {
  importSource.value = 'content'
  importContent.value = ''
  importURL.value = ''
  importFormat.value = 'auto'
  importTags.value = ''
  importPreview.value = null
  importError.value = ''
  importOpen.value = true
}

async function previewImport() {
  importError.value = ''
  importLoading.value = true
  try {
    importPreview.value = await api('/api/nodes/import/preview', {
      method: 'POST',
      body: importPayload()
    })
  } catch (error) {
    importError.value = error instanceof ApiError ? error.message : '预览失败。'
  } finally {
    importLoading.value = false
  }
}

async function doImport() {
  importError.value = ''
  importLoading.value = true
  try {
    const result = await api<{ created: number; skipped: number; issues: unknown[] }>('/api/nodes/import', {
      method: 'POST',
      body: importPayload()
    })
    toast.add({
      title: `已导入 ${result.created} 个节点`,
      description: `跳过 ${result.skipped} 个重复项${result.issues.length ? `，${result.issues.length} 个解析错误` : ''}。`,
      color: result.issues.length ? 'warning' : 'success',
      icon: 'i-lucide-import'
    })
    importOpen.value = false
    await load()
  } catch (error) {
    importError.value = error instanceof ApiError ? error.message : '导入失败。'
  } finally {
    importLoading.value = false
  }
}

function exportNodes() {
  download('/api/nodes/export', 'nyasub-nodes.yaml')
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="mb-5 flex w-fit gap-1 rounded-xl border border-neutral-200 bg-white p-1 dark:border-neutral-800 dark:bg-neutral-900">
      <UButton
        v-for="item in tabItems"
        :key="item.value"
        :icon="item.icon"
        :color="activeTab === item.value ? 'primary' : 'neutral'"
        :variant="activeTab === item.value ? 'soft' : 'ghost'"
        size="sm"
        @click="selectTab(item.value)"
      >
        {{ item.label }}
      </UButton>
    </div>
    <template v-if="activeTab === 'nodes'">
    <div class="mb-6 flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">节点</h1>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
          导入分享链接或 Mihomo YAML，并用标签整理节点。
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <UButton icon="i-lucide-plus" @click="openCreate">添加节点</UButton>
        <UButton icon="i-lucide-upload" color="neutral" variant="subtle" @click="openImport">导入</UButton>
        <UButton icon="i-lucide-download" color="neutral" variant="subtle" @click="exportNodes">导出 YAML</UButton>
      </div>
    </div>

    <UCard>
      <div class="flex flex-col gap-3 border-b border-neutral-200 pb-4 dark:border-neutral-800 lg:flex-row lg:items-center">
        <UInput v-model="search" icon="i-lucide-search" placeholder="搜索名称、服务器或标签…" class="w-full lg:max-w-sm" />
        <div class="flex flex-1 flex-wrap gap-2">
          <USelect v-model="protocolFilter" :items="protocolItems" class="w-44" />
          <USelect v-model="tagFilter" :items="tagItems" class="w-44" />
          <UButton icon="i-lucide-tags" color="neutral" variant="subtle" @click="openTagManager">管理标签</UButton>
          <UButton v-if="selected.length" icon="i-lucide-trash-2" color="error" variant="subtle" @click="askDelete(selected)">
            删除 {{ selected.length }} 项
          </UButton>
        </div>
        <span class="text-xs text-neutral-500">共 {{ nodes.length }} 个节点，显示 {{ filtered.length }} 个</span>
      </div>

      <div v-if="loading" class="space-y-3 py-6">
        <div v-for="i in 5" :key="i" class="h-12 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
      </div>
      <div v-else-if="!filtered.length" class="py-16 text-center">
        <UIcon name="i-lucide-server-off" class="mx-auto size-10 text-neutral-300 dark:text-neutral-700" />
        <h2 class="mt-3 font-medium">没有找到节点</h2>
        <p class="mt-1 text-sm text-neutral-500">调整筛选条件，或添加第一个节点。</p>
        <div class="mt-4 flex justify-center gap-2">
          <UButton icon="i-lucide-plus" @click="openCreate">添加节点</UButton>
          <UButton icon="i-lucide-upload" color="neutral" variant="subtle" @click="openImport">导入</UButton>
        </div>
      </div>
      <div v-else class="overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr>
              <th class="w-10">
                <UCheckbox
                  :model-value="allSelected"
                  aria-label="全选节点"
                  @update:model-value="toggleAll"
                />
              </th>
              <th>名称</th>
              <th>协议</th>
              <th>服务器</th>
              <th>标签</th>
              <th>更新时间</th>
              <th class="w-28 text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="node in filtered" :key="node.id">
              <td>
                <UCheckbox
                  :model-value="selected.includes(node.id)"
                  :aria-label="`选择 ${node.name}`"
                  @update:model-value="(v) => toggleOne(node.id, v)"
                />
              </td>
              <td>
                <button class="text-left font-medium hover:text-pink-600" @click="openEdit(node)">
                  {{ displayName(node.name, node.country) }}
                </button>
              </td>
              <td>
                <UBadge :color="protocolColor(node.protocol)" variant="subtle">{{ protocolLabel(node.protocol) }}</UBadge>
              </td>
              <td class="mono text-xs text-neutral-600 dark:text-neutral-300">{{ hostPort(node.config.server, node.config.port) }}</td>
              <td>
                <div class="flex max-w-56 flex-wrap gap-1">
                  <UBadge v-for="tag in node.tags" :key="tag" color="neutral" variant="subtle" size="sm">{{ tag }}</UBadge>
                  <span v-if="!node.tags.length" class="text-xs text-neutral-400">—</span>
                </div>
              </td>
              <td class="whitespace-nowrap text-xs text-neutral-500">{{ formatDate(node.updated_at) }}</td>
              <td>
                <div class="flex justify-end gap-1">
                  <UButton icon="i-lucide-pencil" size="xs" color="neutral" variant="ghost" aria-label="编辑" @click="openEdit(node)" />
                  <UButton icon="i-lucide-copy" size="xs" color="neutral" variant="ghost" aria-label="复制" @click="copyNode(node)" />
                  <UButton icon="i-lucide-trash-2" size="xs" color="error" variant="ghost" aria-label="删除" @click="askDelete([node.id])" />
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </UCard>

    <UModal v-model:open="formOpen" :title="editID ? '编辑节点' : '添加节点'" description="协议字段会按照 Mihomo 规则进行校验。" :ui="{ content: 'max-w-3xl' }">
      <template #body>
        <form class="space-y-5" @submit.prevent="saveNode">
          <UAlert v-if="formError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="formError" />

          <div class="grid gap-4 sm:grid-cols-2">
            <UFormField label="名称" required>
              <UInput v-model="form.name" placeholder="HK-01" class="w-full" />
            </UFormField>
            <UFormField label="协议" required>
              <USelect v-model="form.protocol" :items="protocolFormItems" class="w-full" />
            </UFormField>
            <UFormField label="服务器" required>
              <UInput v-model="form.config.server" placeholder="hk.example.com" class="w-full" />
            </UFormField>
            <UFormField v-if="showPortField" label="端口" required>
              <UInput v-model="form.port" type="number" min="1" max="65535" class="w-full" />
            </UFormField>
          </div>

          <UFormField label="标签" hint="选择已有标签，或输入后创建">
            <USelectMenu
              v-model="form.tags"
              :items="formTagOptions"
              value-key="value"
              multiple
              create-item
              placeholder="选择或输入标签…"
              class="w-full"
              @create="addFormTag"
            >
              <template #create-item-label="{ item }">创建标签 “{{ item }}”</template>
            </USelectMenu>
            <p class="mt-1 text-xs text-neutral-500">
              标记为“落地机”的节点默认不会进入 ACL4SSR 的「节点选择」和「自动选择」组。
            </p>
          </UFormField>

          <UFormField label="国家/地区" hint="默认从节点名称自动识别，也可以手动指定">
            <USelectMenu
              v-model="form.country"
              :items="countryOptions"
              value-key="value"
              placeholder="自动检测"
              class="w-full"
            />
          </UFormField>

          <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
            <div class="mb-4 flex items-center gap-2 text-sm font-medium">
              <UIcon name="i-lucide-terminal" class="size-4" />
              协议设置
            </div>

            <div class="grid gap-4 sm:grid-cols-2">
              <UFormField v-if="['vless', 'vmess', 'tuic'].includes(form.protocol)" label="UUID" required class="sm:col-span-2">
                <UInput v-model="form.config.uuid" placeholder="00000000-0000-4000-8000-000000000000" class="w-full mono" />
              </UFormField>

              <UFormField v-if="form.protocol === 'vmess'" label="Alter ID">
                <UInput v-model.number="form.config.alter_id" type="number" min="0" class="w-full" />
              </UFormField>
              <UFormField v-if="form.protocol === 'vmess'" label="加密方式">
                <UInput v-model="form.config.cipher" placeholder="auto" class="w-full" />
              </UFormField>

              <UFormField v-if="['trojan', 'ss', 'hysteria2', 'tuic'].includes(form.protocol)" label="密码" required class="sm:col-span-2">
                <UInput v-model="form.config.password" type="password" class="w-full" />
              </UFormField>
              <UFormField v-if="form.protocol === 'ss'" label="加密方式" required>
                <UInput v-model="form.config.cipher" placeholder="aes-256-gcm" class="w-full" />
              </UFormField>
              <UFormField v-if="['socks5', 'http', 'ssh'].includes(form.protocol)" label="用户名" :required="form.protocol === 'ssh'">
                <UInput v-model="form.config.username" class="w-full" />
              </UFormField>
              <UFormField v-if="['socks5', 'http', 'ssh'].includes(form.protocol)" label="密码">
                <UInput v-model="form.config.password" type="password" class="w-full" />
              </UFormField>

              <div v-if="form.protocol === 'ssh'" class="contents">
                <UFormField label="私钥" hint="PEM 内容或服务器上的文件路径；与密码至少填写一项" class="sm:col-span-2">
                  <UTextarea v-model="form.config.private_key" :rows="6" class="w-full mono" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                </UFormField>
                <UFormField label="私钥口令">
                  <UInput v-model="form.config.private_key_passphrase" type="password" class="w-full" />
                </UFormField>
                <UFormField label="Host Key" hint="每行一个 authorized_keys 条目；留空则接受所有">
                  <UTextarea v-model="form.hostKeys" :rows="3" class="w-full mono" placeholder="ssh-ed25519 AAAA..." />
                </UFormField>
                <UFormField label="Host Key 算法" hint="逗号分隔，例如 ssh-ed25519, rsa-sha2-256" class="sm:col-span-2">
                  <UInput v-model="form.hostKeyAlgorithms" class="w-full mono" />
                </UFormField>
              </div>

              <UFormField v-if="form.protocol === 'vless'" label="Flow">
                <UInput v-model="form.config.flow" placeholder="xtls-rprx-vision" class="w-full" />
              </UFormField>

              <UFormField
                v-if="form.protocol === 'vless'"
                label="VLESS 加密（encryption）"
                hint="留空表示 none"
                class="sm:col-span-2"
              >
                <UTextarea
                  v-model="form.config.encryption"
                  :rows="2"
                  class="w-full mono"
                  placeholder="mlkem768x25519plus.native.0rtt.…"
                />
              </UFormField>

              <UFormField v-if="showTransport" label="传输方式">
                <USelect v-model="form.config.network" :items="form.protocol === 'trojan' ? tcpOnlyNetworks : networkItems" class="w-full" />
              </UFormField>

              <UFormField v-if="form.config.network === 'ws' && showTransport" label="WebSocket 路径">
                <UInput v-model="form.config.ws!.path" placeholder="/ws" class="w-full mono" />
              </UFormField>
              <UFormField v-if="form.config.network === 'ws' && showTransport" label="WebSocket Host 头">
                <UInput v-model="form.config.ws!.headers!.Host" placeholder="example.com" class="w-full" />
              </UFormField>
              <UFormField v-if="form.config.network === 'grpc' && showTransport" label="gRPC 服务名">
                <UInput v-model="form.config.grpc!.service_name" placeholder="grpc-service" class="w-full" />
              </UFormField>

              <UFormField v-if="showSNI" label="SNI / 服务器名称">
                <UInput v-model="form.config.sni" placeholder="example.com" class="w-full" />
              </UFormField>
              <UFormField v-if="showSNI" label="ALPN" hint="用逗号分隔">
                <UInput v-model="form.alpn" placeholder="h2, http/1.1" class="w-full" />
              </UFormField>
              <UFormField v-if="showTLS || form.protocol === 'trojan' || form.protocol === 'hysteria2' || form.protocol === 'tuic'" label="指纹">
                <UInput v-model="form.config.fingerprint" placeholder="chrome" class="w-full" />
              </UFormField>
            </div>

            <div v-if="showTLS" class="mt-4 flex flex-wrap gap-6">
              <USwitch v-model="form.config.tls" label="TLS" />
              <USwitch v-model="form.config.skip_cert_verify" label="跳过证书校验" />
            </div>
            <div v-if="['trojan', 'hysteria2', 'tuic'].includes(form.protocol)" class="mt-4">
              <USwitch v-model="form.config.skip_cert_verify" label="跳过证书校验" />
            </div>

            <div v-if="showReality" class="mt-5 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
              <div class="mb-3 text-sm font-medium">REALITY</div>
              <div class="grid gap-4 sm:grid-cols-2">
                <UFormField label="公钥">
                  <UInput v-model="form.config.reality!.public_key" class="w-full mono" placeholder="Base64 公钥" />
                </UFormField>
                <UFormField label="Short ID">
                  <UInput v-model="form.config.reality!.short_id" class="w-full mono" placeholder="十六进制 Short ID" />
                </UFormField>
              </div>
            </div>

            <div v-if="form.protocol === 'hysteria2'" class="mt-4 grid gap-4 sm:grid-cols-2">
              <UFormField label="混淆方式">
                <UInput v-model="form.config.obfs" placeholder="salamander" class="w-full" />
              </UFormField>
              <UFormField label="混淆密码">
                <UInput v-model="form.config.obfs_password" type="password" class="w-full" />
              </UFormField>
              <UFormField label="上行速率">
                <UInput v-model="form.config.up" placeholder="50 mbps" class="w-full" />
              </UFormField>
              <UFormField label="下行速率">
                <UInput v-model="form.config.down" placeholder="100 mbps" class="w-full" />
              </UFormField>
            </div>

            <div v-if="form.protocol === 'tuic'" class="mt-4 grid gap-4 sm:grid-cols-2">
              <UFormField label="拥塞控制算法">
                <UInput v-model="form.config.congestion_controller" placeholder="bbr" class="w-full" />
              </UFormField>
              <UFormField label="UDP 中继模式">
                <UInput v-model="form.config.udp_relay_mode" placeholder="native" class="w-full" />
              </UFormField>
            </div>
            <div v-if="['vless', 'vmess', 'trojan', 'ss', 'socks5', 'tuic'].includes(form.protocol)" class="mt-4 flex flex-wrap gap-6">
              <USwitch v-if="['vless', 'vmess', 'trojan', 'ss', 'socks5'].includes(form.protocol)" v-model="form.config.udp" label="UDP 中继" />
              <USwitch v-if="form.protocol === 'tuic'" v-model="form.config.disable_sni" label="禁用 SNI" />
              <USwitch v-if="form.protocol === 'tuic'" v-model="form.config.reduce_rtt" label="减少 RTT" />
            </div>

            <div v-if="form.protocol === 'ss'" class="mt-4 grid gap-4 sm:grid-cols-2">
              <UFormField label="插件">
                <UInput v-model="form.config.plugin" placeholder="obfs 或 v2ray-plugin" class="w-full" />
              </UFormField>
              <UFormField label="插件参数（JSON）">
                <UTextarea v-model="form.pluginOpts" :rows="3" class="w-full mono" placeholder='{"mode":"http","host":"example.com"}' />
              </UFormField>
              <div class="flex items-end pb-2">
                <USwitch v-model="form.config.udp_over_tcp" label="UDP over TCP" />
              </div>
              <UFormField v-if="form.config.udp_over_tcp" label="UDP over TCP 版本">
                <USelect
                  v-model="form.config.udp_over_tcp_version"
                  :items="[{ label: 'v1', value: 1 }, { label: 'v2', value: 2 }]"
                  class="w-full"
                />
              </UFormField>
            </div>
          </div>

          <details class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
            <summary class="cursor-pointer text-sm font-medium">高级字段（JSON）</summary>
            <p class="mt-2 text-xs text-neutral-500">保留上方未展示的 Mihomo 字段（例如 <span class="mono">smux</span>、<span class="mono">tfo</span>）。</p>
            <UTextarea v-model="form.extra" :rows="4" class="mt-3 w-full mono" placeholder='{"tfo": true}' />
          </details>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="formOpen = false">取消</UButton>
          <UButton :loading="saving" icon="i-lucide-save" @click="saveNode">保存节点</UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="importOpen" title="导入节点" description="建议先预览。系统会根据协议、地址和凭据识别重复节点。" :ui="{ content: 'max-w-3xl' }">
      <template #body>
        <div class="space-y-4">
          <UAlert v-if="importError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="importError" />
          <div class="grid gap-4 sm:grid-cols-2">
            <UFormField label="来源">
              <USelect v-model="importSource" :items="importSourceItems" class="w-full" />
            </UFormField>
            <UFormField label="标签" hint="应用于本次导入的所有节点">
              <UInput v-model="importTags" placeholder="导入" class="w-full" />
            </UFormField>
          </div>
          <UFormField v-if="importSource === 'content'" label="格式">
            <USelect v-model="importFormat" :items="importFormatItems" class="w-full" />
          </UFormField>
          <UFormField
            v-if="importSource === 'content'"
            label="内容"
            hint="最大 1 MiB / 500 个节点，支持 Base64 编码的 V2Ray 订阅内容"
          >
            <UTextarea
              v-model="importContent"
              :rows="10"
              class="w-full mono"
              placeholder="vless://…&#10;vmess://…&#10;&#10;或&#10;&#10;proxies:&#10;  - name: HK-01&#10;    type: vless&#10;    …"
            />
          </UFormField>
          <UFormField
            v-else
            label="订阅 URL"
            hint="由服务器抓取并自动识别 V2Ray Base64 或 Mihomo/Clash YAML"
          >
            <UInput
              v-model="importURL"
              type="url"
              class="w-full mono"
              placeholder="https://example.com/api/v1/client/subscribe?token=…"
            />
            <p class="mt-2 text-xs text-neutral-500">
              仅允许公网 http(s) 地址。订阅链接可能包含敏感 Token，不会写入访问日志。
            </p>
          </UFormField>

          <div v-if="importPreview" class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
              <UBadge color="success" variant="subtle">已解析 {{ importPreview.items.length }} 个</UBadge>
              <UBadge color="warning" variant="subtle">{{ importPreview.duplicate_count }} 个重复</UBadge>
              <UBadge v-if="importPreview.issues?.length" color="error" variant="subtle">{{ importPreview.issues?.length }} 个错误</UBadge>
            </div>
            <div class="max-h-56 overflow-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
              <table class="data-table min-w-0">
                <thead><tr><th>名称</th><th>协议</th><th>状态</th></tr></thead>
                <tbody>
                  <tr v-for="(item, index) in importPreview.items" :key="index">
                    <td class="font-medium">{{ item.name }}</td>
                    <td><UBadge color="neutral" variant="subtle" size="sm">{{ protocolLabel(item.protocol) }}</UBadge></td>
                    <td>
                      <UBadge :color="item.duplicate ? 'warning' : 'success'" variant="subtle" size="sm">
                        {{ item.duplicate ? `重复${item.existing_name ? `：${item.existing_name}` : ''}` : '新增' }}
                      </UBadge>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-if="importPreview.issues?.length" class="max-h-40 overflow-auto rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
              <p v-for="(issue, index) in (importPreview.issues || [])" :key="index" class="mono">
第 {{ issue.line }} 行：{{ issue.message }}
              </p>
            </div>
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full flex-wrap justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="importOpen = false">取消</UButton>
          <UButton color="neutral" variant="subtle" icon="i-lucide-eye" :loading="importLoading" :disabled="!importReady" @click="previewImport">
            {{ importSource === 'url' ? '获取并预览' : '预览' }}
          </UButton>
          <UButton icon="i-lucide-import" :loading="importLoading" :disabled="!importReady" @click="doImport">
            导入
          </UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="tagManagerOpen" title="标签管理" description="删除标签只会从所有节点移除该标签，不会删除节点。" :ui="{ content: 'max-w-lg' }">
      <template #body>
        <div v-if="tagManagerLoading" class="space-y-2">
          <div v-for="i in 3" :key="i" class="h-12 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
        </div>
        <div v-else-if="!tagCounts.length" class="py-10 text-center text-sm text-neutral-500">
          暂无标签。先在节点编辑里创建标签。
        </div>
        <div v-else class="space-y-2">
          <div
            v-for="tag in tagCounts"
            :key="tag.name"
            class="flex items-center justify-between gap-3 rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
          >
            <div class="flex min-w-0 items-center gap-2">
              <UBadge color="neutral" variant="subtle">{{ tag.name }}</UBadge>
              <span class="text-xs text-neutral-500">{{ tag.count }} 个节点</span>
            </div>
            <UButton
              icon="i-lucide-trash-2"
              size="xs"
              color="error"
              variant="ghost"
              :aria-label="`删除标签 ${tag.name}`"
              @click="askDeleteTag(tag.name)"
            />
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end">
          <UButton color="neutral" variant="ghost" @click="tagManagerOpen = false">关闭</UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="tagDeleteOpen" title="删除标签" :ui="{ content: 'max-w-md' }">
      <template #body>
        <div class="space-y-4">
          <p class="text-sm text-neutral-600 dark:text-neutral-300">
            确定删除标签 <span class="font-medium">“{{ tagDeleteTarget }}”</span>？
            它会从 {{ tagCounts.find((item) => item.name === tagDeleteTarget)?.count || 0 }} 个节点上移除，但不会删除任何节点。
          </p>
          <UAlert v-if="tagDeleteError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="tagDeleteError" />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="tagDeleteOpen = false">取消</UButton>
          <UButton color="error" icon="i-lucide-trash-2" :loading="deletingTag" @click="confirmDeleteTag">删除标签</UButton>
        </div>
      </template>
    </UModal>

    <UModal v-model:open="deleteOpen" title="删除节点" :ui="{ content: 'max-w-md' }">
      <template #body>
        <div class="space-y-4">
          <p class="text-sm text-neutral-600 dark:text-neutral-300">
            确定删除选中的 {{ deleteTargets.length }} 个节点？被链式代理引用的节点始终无法删除；订阅配置可以通过强制删除来移除引用。
          </p>
          <UAlert v-if="deleteError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="deleteError" />
          <UCheckbox v-model="deleteForce" label="强制从订阅配置中移除（不会删除链式代理）" />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="deleteOpen = false">取消</UButton>
          <UButton color="error" icon="i-lucide-trash-2" :loading="deleting" @click="confirmDelete">删除</UButton>
        </div>
      </template>
    </UModal>
    </template>
    <ChainManager v-else />
  </div>
</template>
