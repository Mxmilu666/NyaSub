<script setup lang="ts">
const route = useRoute()
const profileId = computed(() => String(route.params.id || ''))
useHead({ title: '编辑订阅配置' })
</script>

<template>
  <ProfileEditor :profile-id="profileId" />
</template>
