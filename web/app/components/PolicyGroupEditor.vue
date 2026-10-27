<script setup lang="ts">
import type { PolicyGroup } from '~/types/api'

const props = defineProps<{
  group: PolicyGroup
  proxyOptions: Array<{ label: string; value: string }>
  index: number
}>()

const emit = defineEmits<{ remove: [number] }>()

const groupTypeItems = [
  { label: '选择', value: 'select' },
  { label: 'URL 测速', value: 'url-test' },
  { label: '故障转移', value: 'fallback' },
  { label: '负载均衡', value: 'load-balance' }
]
const strategyItems = [
  { label: '轮询', value: 'round-robin' },
  { label: '一致性哈希', value: 'consistent-hashing' },
  { label: '粘性会话', value: 'sticky-sessions' }
]
</script>

<template>
  <div class="rounded-xl border border-neutral-200 p-4 dark:border-neutral-800">
    <div class="grid gap-3 sm:grid-cols-2">
      <UFormField label="名称">
        <UInput v-model="props.group.name" class="w-full" />
      </UFormField>
      <UFormField label="类型">
        <USelect v-model="props.group.type" :items="groupTypeItems" class="w-full" />
      </UFormField>
      <UFormField label="代理成员" class="sm:col-span-2">
        <USelectMenu v-model="props.group.proxies" :items="props.proxyOptions" value-key="value" multiple placeholder="选择代理…" class="w-full" />
      </UFormField>
      <div v-if="props.group.type !== 'select'" class="contents">
        <UFormField label="测速 URL">
          <UInput v-model="props.group.url" placeholder="https://www.gstatic.com/generate_204" class="w-full" />
        </UFormField>
        <UFormField label="间隔（秒）">
          <UInput v-model.number="props.group.interval" type="number" min="1" class="w-full" />
        </UFormField>
        <UFormField label="容差（毫秒）">
          <UInput v-model.number="props.group.tolerance" type="number" min="0" class="w-full" />
        </UFormField>
        <div class="flex items-end pb-2">
          <USwitch v-model="props.group.lazy" label="懒加载" />
        </div>
        <UFormField v-if="props.group.type === 'load-balance'" label="负载均衡策略">
          <USelect v-model="props.group.strategy" :items="strategyItems" class="w-full" />
        </UFormField>
      </div>
    </div>
    <div class="mt-3 flex justify-end">
      <UButton size="xs" color="error" variant="ghost" icon="i-lucide-trash-2" @click="emit('remove', props.index)">删除策略组</UButton>
    </div>
  </div>
</template>
