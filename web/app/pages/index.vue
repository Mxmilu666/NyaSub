<script setup lang="ts">
import type { DashboardData, NodeItem } from '~/types/api'

useHead({ title: '仪表盘' })

const { api } = useApi()
const { protocolColor, protocolLabel, timeAgo } = useFormat()
const toast = useToast()
const data = ref<DashboardData | null>(null)
const nodes = ref<NodeItem[]>([])
const loading = ref(true)

const cards = computed(() => [
  { key: 'nodes', label: '节点', icon: 'i-lucide-server', color: 'primary', to: '/nodes' },
  { key: 'chains', label: '链式代理', icon: 'i-lucide-link-2', color: 'info', to: '/nodes?tab=chains' },
  { key: 'profiles', label: '订阅配置', icon: 'i-lucide-file-code-2', color: 'success', to: '/profiles' },
  { key: 'active_tokens', label: '有效订阅', icon: 'i-lucide-key-round', color: 'warning', to: '/profiles' }
] as const)

async function load() {
  loading.value = true
  try {
    const [dashboard, nodeData] = await Promise.all([
      api<DashboardData>('/api/dashboard'),
      api<{ nodes: NodeItem[] }>('/api/nodes')
    ])
    data.value = dashboard
    nodes.value = nodeData.nodes.slice(0, 8)
  } catch (error) {
    toast.add({ title: '加载仪表盘失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="mb-8 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">仪表盘</h1>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">快速查看节点、链式代理和订阅状态。</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <UButton to="/nodes" icon="i-lucide-plus" color="primary">添加节点</UButton>
        <UButton to="/nodes?tab=chains" icon="i-lucide-link" color="neutral" variant="subtle">新建链路</UButton>
        <UButton to="/profiles/new" icon="i-lucide-file-plus-2" color="neutral" variant="subtle">新建配置</UButton>
      </div>
    </div>

    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <UCard
        v-for="card in cards"
        :key="card.key"
        class="transition-colors hover:border-neutral-300 dark:hover:border-neutral-700"
      >
        <NuxtLink :to="card.to" class="block">
          <div class="flex items-start justify-between">
            <div>
              <p class="text-sm font-medium text-neutral-500 dark:text-neutral-400">{{ card.label }}</p>
              <p class="mt-2 text-3xl font-semibold tracking-tight">
                <span v-if="loading" class="inline-block h-8 w-12 animate-pulse rounded bg-neutral-200 dark:bg-neutral-800" />
                <span v-else>{{ card.key === 'active_tokens' ? data?.stats.active_tokens : data?.stats[card.key as 'nodes' | 'chains' | 'profiles'] }}</span>
              </p>
            </div>
            <div class="rounded-xl bg-neutral-100 p-2.5 dark:bg-neutral-800">
              <UIcon :name="card.icon" class="size-5 text-neutral-600 dark:text-neutral-300" />
            </div>
          </div>
          <p v-if="card.key === 'chains' && data" class="mt-3 text-xs text-neutral-500">
            {{ data.stats.enabled_chains }} 条已启用
          </p>
          <p v-else-if="card.key === 'profiles'" class="mt-3 text-xs text-neutral-500">
            固定订阅地址
          </p>
          <p v-else-if="card.key === 'nodes'" class="mt-3 text-xs text-neutral-500">
            手动创建或批量导入
          </p>
          <p v-else class="mt-3 text-xs text-neutral-500">
            仅通过令牌授权
          </p>
        </NuxtLink>
      </UCard>
    </div>

    <UCard class="mt-6">
      <template #header>
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 class="font-semibold">节点</h2>
            <p class="text-xs text-neutral-500">名称、协议、地址和标签。</p>
          </div>
          <UButton to="/nodes" size="xs" color="neutral" variant="ghost" trailing-icon="i-lucide-arrow-right">管理节点</UButton>
        </div>
      </template>
      <div v-if="loading" class="space-y-2">
        <div v-for="i in 3" :key="i" class="h-9 animate-pulse rounded bg-neutral-100 dark:bg-neutral-800" />
      </div>
      <div v-else-if="!nodes.length" class="py-6 text-center text-sm text-neutral-500">
        暂无节点。<NuxtLink to="/nodes" class="text-pink-600 hover:underline">立即导入或添加</NuxtLink>。
      </div>
      <div v-else class="overflow-x-auto">
        <table class="data-table">
          <thead>
            <tr><th>名称</th><th>协议</th><th>服务器</th><th>端口</th><th>标签</th></tr>
          </thead>
          <tbody>
            <tr v-for="node in nodes" :key="node.id">
              <td class="font-medium">{{ node.name }}</td>
              <td><UBadge :color="protocolColor(node.protocol)" variant="subtle" size="sm">{{ protocolLabel(node.protocol) }}</UBadge></td>
              <td class="mono text-xs">{{ node.config.server }}</td>
              <td class="mono text-xs">{{ node.config.port }}</td>
              <td>
                <div class="flex flex-wrap gap-1">
                  <UBadge v-for="tag in node.tags" :key="tag" color="neutral" variant="subtle" size="sm">{{ tag }}</UBadge>
                  <span v-if="!node.tags.length" class="text-xs text-neutral-400">—</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </UCard>

    <div class="mt-6 grid gap-6 lg:grid-cols-5">
      <UCard class="lg:col-span-3">
        <template #header>
          <div class="flex items-center justify-between">
            <div>
              <h2 class="font-semibold">最近更新</h2>
              <p class="text-xs text-neutral-500">按修改时间排序的节点与订阅配置。</p>
            </div>
            <UButton icon="i-lucide-refresh-cw" size="xs" color="neutral" variant="ghost" :loading="loading" @click="load" />
          </div>
        </template>

        <div v-if="loading" class="space-y-3 py-2">
          <div v-for="i in 4" :key="i" class="h-10 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
        </div>
        <div v-else-if="!data?.recent.length" class="py-10 text-center">
          <UIcon name="i-lucide-inbox" class="mx-auto size-8 text-neutral-300 dark:text-neutral-700" />
          <p class="mt-2 text-sm text-neutral-500">暂无内容，先添加一个节点开始使用。</p>
        </div>
        <ul v-else class="divide-y divide-neutral-100 dark:divide-neutral-900">
          <li v-for="item in data.recent" :key="`${item.type}-${item.id}`">
            <NuxtLink
              :to="item.type === 'profile' ? `/profiles/${item.id}/edit` : '/nodes'"
              class="flex items-center justify-between gap-3 py-3"
            >
              <div class="flex min-w-0 items-center gap-3">
                <div class="rounded-lg bg-neutral-100 p-2 dark:bg-neutral-800">
                  <UIcon :name="item.type === 'profile' ? 'i-lucide-file-code-2' : 'i-lucide-server'" class="size-4" />
                </div>
                <div class="min-w-0">
                  <p class="truncate text-sm font-medium">{{ item.name }}</p>
                  <p class="text-xs text-neutral-500">{{ item.type === 'profile' ? '订阅配置' : '节点' }}</p>
                </div>
              </div>
              <span class="shrink-0 text-xs text-neutral-500">{{ timeAgo(item.updated_at) }}</span>
            </NuxtLink>
          </li>
        </ul>
      </UCard>

      <UCard class="lg:col-span-2">
        <template #header>
          <h2 class="font-semibold">使用流程</h2>
        </template>
        <div class="space-y-5 text-sm">
          <div class="flex gap-3">
            <div class="flex size-7 shrink-0 items-center justify-center rounded-full bg-pink-100 text-xs font-semibold text-pink-700 dark:bg-pink-950 dark:text-pink-300">1</div>
            <div>
              <p class="font-medium">导入节点</p>
              <p class="mt-0.5 text-neutral-500 dark:text-neutral-400">粘贴分享链接或 Mihomo proxies 数组，保存前先预览。</p>
            </div>
          </div>
          <div class="flex gap-3">
            <div class="flex size-7 shrink-0 items-center justify-center rounded-full bg-pink-100 text-xs font-semibold text-pink-700 dark:bg-pink-950 dark:text-pink-300">2</div>
            <div>
              <p class="font-medium">创建链式代理</p>
              <p class="mt-0.5 text-neutral-500 dark:text-neutral-400">选择入口和出口节点，NyaSub 会通过 <span class="mono text-xs">dialer-proxy</span> 生成链路。</p>
            </div>
          </div>
          <div class="flex gap-3">
            <div class="flex size-7 shrink-0 items-center justify-center rounded-full bg-pink-100 text-xs font-semibold text-pink-700 dark:bg-pink-950 dark:text-pink-300">3</div>
            <div>
              <p class="font-medium">发布订阅配置</p>
              <p class="mt-0.5 text-neutral-500 dark:text-neutral-400">选择节点、链路、策略组和规则，生成固定订阅地址。</p>
            </div>
          </div>
        </div>
        <div class="mt-6 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
          <div class="flex gap-2">
            <UIcon name="i-lucide-shield-alert" class="mt-0.5 size-4 shrink-0" />
            <span>订阅令牌只显示一次，请妥善保存；数据库中只保留哈希。</span>
          </div>
        </div>
      </UCard>
    </div>
  </div>
</template>
