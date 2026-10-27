<script setup lang="ts">
import { ApiError } from '~/composables/useApi'

definePageMeta({ layout: 'auth' })
useHead({ title: '登录' })

const auth = useAuth()
const toast = useToast()
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  if (!username.value.trim() || !password.value) {
    error.value = '请输入用户名和密码。'
    return
  }
  loading.value = true
  try {
    await auth.login(username.value.trim(), password.value)
    toast.add({ title: '欢迎回来', icon: 'i-lucide-check-circle-2' })
    await navigateTo('/')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '登录失败，请重试。'
    if (e instanceof ApiError && e.code === 'not_initialized') {
      await navigateTo('/setup')
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <UCard class="shadow-xl shadow-neutral-950/5">
    <template #header>
      <div>
        <h2 class="text-lg font-semibold">登录</h2>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">使用初始化时创建的管理员账号登录。</p>
      </div>
    </template>

    <form class="space-y-4" @submit.prevent="submit">
      <UAlert
        v-if="error"
        color="error"
        variant="subtle"
        icon="i-lucide-circle-alert"
        :title="error"
      />

      <UFormField label="用户名">
        <UInput v-model="username" autocomplete="username" placeholder="admin" autofocus class="w-full" size="lg" />
      </UFormField>

      <UFormField label="密码">
        <UInput v-model="password" type="password" autocomplete="current-password" placeholder="••••••••••" class="w-full" size="lg" />
      </UFormField>

      <UButton type="submit" block size="lg" :loading="loading" icon="i-lucide-log-in">
        登录
      </UButton>
    </form>
  </UCard>
</template>
