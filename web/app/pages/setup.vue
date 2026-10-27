<script setup lang="ts">
import { ApiError } from '~/composables/useApi'

definePageMeta({ layout: 'auth' })
useHead({ title: '创建管理员' })

const auth = useAuth()
const toast = useToast()
const username = ref('')
const password = ref('')
const confirm = ref('')
const error = ref('')
const loading = ref(false)
const usernamePattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$/

async function submit() {
  error.value = ''
  const name = username.value.trim()
  if (!usernamePattern.test(name)) {
    error.value = '用户名需为 3–32 个字符，以字母或数字开头，可包含字母、数字、点、短横线或下划线。'
    return
  }
  if (password.value.length < 10) {
    error.value = '密码至少需要 10 个字符。'
    return
  }
  if (password.value !== confirm.value) {
    error.value = '两次输入的密码不一致。'
    return
  }
  loading.value = true
  try {
    await auth.setup(name, password.value)
    toast.add({ title: '管理员创建成功', icon: 'i-lucide-shield-check' })
    await navigateTo('/')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : '初始化失败，请重试。'
    if (e instanceof ApiError && e.code === 'already_initialized') {
      await navigateTo('/login')
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
        <h2 class="text-lg font-semibold">创建管理员账号</h2>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
          这是唯一的账号。初始化只能执行一次。
        </p>
      </div>
    </template>

    <form class="space-y-4" @submit.prevent="submit">
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" />

      <UFormField label="用户名" hint="3–32 个字符">
        <UInput v-model="username" autocomplete="username" placeholder="admin" autofocus class="w-full" size="lg" />
      </UFormField>

      <UFormField label="密码" hint="至少 10 个字符">
        <UInput v-model="password" type="password" autocomplete="new-password" placeholder="设置一个强密码" class="w-full" size="lg" />
      </UFormField>

      <UFormField label="确认密码">
        <UInput v-model="confirm" type="password" autocomplete="new-password" placeholder="再次输入密码" class="w-full" size="lg" />
      </UFormField>

      <UButton type="submit" block size="lg" :loading="loading" icon="i-lucide-shield-check">
        创建管理员
      </UButton>
    </form>
  </UCard>
</template>
