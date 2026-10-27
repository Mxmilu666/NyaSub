<script setup lang="ts">
const auth = useAuth()
const route = useRoute()
const toast = useToast()
const signingOut = ref(false)

const nav = [
  { label: '仪表盘', to: '/', icon: 'i-lucide-layout-dashboard' },
  { label: '节点与链路', to: '/nodes', icon: 'i-lucide-server' },
  { label: '订阅配置', to: '/profiles', icon: 'i-lucide-file-code-2' },
  { label: '设置', to: '/settings', icon: 'i-lucide-settings-2' }
]

function isActive(to: string) {
  if (to === '/') return route.path === '/'
  return route.path === to || route.path.startsWith(`${to}/`)
}

async function signOut() {
  if (signingOut.value) return
  signingOut.value = true
  try {
    await auth.logout()
    toast.add({ title: '已退出登录', icon: 'i-lucide-log-out' })
    await navigateTo('/login')
  } catch (error) {
    toast.add({ title: '退出登录失败', description: (error as Error).message, color: 'error', icon: 'i-lucide-triangle-alert' })
  } finally {
    signingOut.value = false
  }
}
</script>

<template>
  <div class="min-h-screen bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
    <aside class="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col border-r border-neutral-200 bg-white/90 backdrop-blur dark:border-neutral-800 dark:bg-neutral-900/80 lg:flex">
      <div class="flex h-16 items-center gap-3 border-b border-neutral-200 px-5 dark:border-neutral-800">
        <div class="flex size-9 items-center justify-center rounded-xl bg-pink-600 text-white shadow-sm">
          <UIcon name="i-lucide-orbit" class="size-5" />
        </div>
        <div class="min-w-0">
          <div class="text-base font-semibold leading-tight">NyaSub</div>
          <div class="text-[11px] text-neutral-500 dark:text-neutral-400">Mihomo 订阅管理</div>
        </div>
      </div>

      <nav class="flex-1 space-y-1 overflow-y-auto p-3">
        <NuxtLink
          v-for="item in nav"
          :key="item.to"
          :to="item.to"
          class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors"
          :class="isActive(item.to)
            ? 'bg-pink-50 text-pink-700 dark:bg-pink-950/60 dark:text-pink-300'
            : 'text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800/70 dark:hover:text-neutral-100'"
        >
          <UIcon :name="item.icon" class="size-4.5 shrink-0" />
          <span>{{ item.label }}</span>
        </NuxtLink>
      </nav>

      <div class="border-t border-neutral-200 p-3 dark:border-neutral-800">
        <div class="flex items-center justify-between gap-2 rounded-lg px-2 py-2">
          <div class="min-w-0">
            <div class="truncate text-sm font-medium">{{ auth.user.value?.username }}</div>
            <div class="text-[11px] text-neutral-500">管理员</div>
          </div>
          <div class="flex items-center gap-1">
            <UColorModeButton size="xs" color="neutral" variant="ghost" />
            <UButton
              icon="i-lucide-log-out"
              size="xs"
              color="neutral"
              variant="ghost"
              :loading="signingOut"
              aria-label="退出登录"
              @click="signOut"
            />
          </div>
        </div>
      </div>
    </aside>

    <div class="lg:pl-64">
      <header class="sticky top-0 z-20 border-b border-neutral-200 bg-white/85 backdrop-blur dark:border-neutral-800 dark:bg-neutral-950/85 lg:hidden">
        <div class="flex h-14 items-center justify-between px-4">
          <div class="flex items-center gap-2">
            <div class="flex size-8 items-center justify-center rounded-lg bg-pink-600 text-white">
              <UIcon name="i-lucide-orbit" class="size-4" />
            </div>
            <span class="font-semibold">NyaSub</span>
          </div>
          <div class="flex items-center gap-1">
            <UColorModeButton size="sm" color="neutral" variant="ghost" />
            <UButton icon="i-lucide-log-out" size="sm" color="neutral" variant="ghost" :loading="signingOut" @click="signOut" />
          </div>
        </div>
        <nav class="flex gap-1 overflow-x-auto px-3 pb-2 scroll-thin">
          <NuxtLink
            v-for="item in nav"
            :key="item.to"
            :to="item.to"
            class="flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium"
            :class="isActive(item.to)
              ? 'bg-pink-50 text-pink-700 dark:bg-pink-950/60 dark:text-pink-300'
              : 'text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-800'"
          >
            <UIcon :name="item.icon" class="size-4" />
            {{ item.label }}
          </NuxtLink>
        </nav>
      </header>

      <main>
        <slot />
      </main>
    </div>
  </div>
</template>
