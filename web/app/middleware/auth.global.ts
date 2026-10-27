export default defineNuxtRouteMiddleware(async (to) => {
  const auth = useAuth()

  if (to.path === '/setup') {
    const initialized = await auth.loadStatus(true)
    if (initialized) return navigateTo('/login')
    return
  }

  const initialized = await auth.loadStatus()
  if (!initialized) return navigateTo('/setup')

  if (!auth.checked.value) await auth.refreshUser()

  if (to.path === '/login') {
    if (auth.user.value) return navigateTo('/')
    return
  }

  if (!auth.user.value) return navigateTo('/login')
})
