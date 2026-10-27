export default defineNuxtConfig({
  modules: ['@nuxt/ui'],
  css: ['~/assets/css/main.css'],
  ssr: false,
  compatibilityDate: '2025-07-15',
  devtools: { enabled: false },
  typescript: {
    strict: true,
    typeCheck: false
  },
  ui: {
    colorMode: true
  },
  icon: {
    clientBundle: {
      scan: true,
      icons: [
        'lucide:layout-dashboard',
        'lucide:server',
        'lucide:link-2',
        'lucide:file-code-2',
        'lucide:settings-2',
        'lucide:orbit',
        'lucide:shield-check'
      ]
    }
  },
  nitro: {
    devProxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
      '/s': { target: 'http://127.0.0.1:8080', changeOrigin: true }
    }
  },
  app: {
    head: {
      htmlAttrs: { lang: 'zh-CN' },
      title: '仪表盘',
      titleTemplate: '%s · NyaSub',
      meta: [
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'description', content: '自托管的 Mihomo 节点、链式代理与订阅管理平台' },
        { name: 'theme-color', content: '#0b1120' }
      ],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }]
    }
  }
})
