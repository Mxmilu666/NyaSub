<template>
  <div class="relative flex min-h-screen items-center justify-center overflow-hidden bg-neutral-50 px-4 py-10 dark:bg-neutral-950">
    <div class="pointer-events-none absolute -top-40 left-1/2 size-[36rem] -translate-x-1/2 rounded-full bg-pink-500/10 blur-3xl" />
    <div class="pointer-events-none absolute -bottom-52 right-0 size-[32rem] rounded-full bg-cyan-500/10 blur-3xl" />
    <div class="relative w-full max-w-md">
      <div class="mb-8 flex flex-col items-center text-center">
        <div class="mb-4 flex size-14 items-center justify-center rounded-2xl bg-pink-600 text-white shadow-lg shadow-pink-600/20">
          <UIcon name="i-lucide-orbit" class="size-7" />
        </div>
        <h1 class="text-2xl font-semibold tracking-tight">NyaSub</h1>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">轻量级 Mihomo 订阅管理</p>
      </div>
      <slot />
      <div class="mt-8 flex items-center justify-center gap-2 text-xs text-neutral-400">
        <UIcon name="i-lucide-shield-check" class="size-3.5" />
        <span>管理凭据绝不会进入订阅 URL</span>
      </div>
    </div>
  </div>
</template>
