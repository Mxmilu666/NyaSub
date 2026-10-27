import type { Protocol } from '~/types/api'

const labels: Record<Protocol, string> = {
  vless: 'VLESS',
  vmess: 'VMess',
  trojan: 'Trojan',
  ss: 'Shadowsocks',
  hysteria2: 'Hysteria2',
  tuic: 'TUIC',
  socks5: 'SOCKS5',
  http: 'HTTP',
  ssh: 'SSH'
}

const colors: Record<Protocol, 'primary' | 'info' | 'success' | 'warning' | 'error' | 'neutral'> = {
  vless: 'primary',
  vmess: 'info',
  trojan: 'warning',
  ss: 'success',
  hysteria2: 'error',
  tuic: 'info',
  socks5: 'neutral',
  http: 'neutral',
  ssh: 'warning'
}

export function useFormat() {
  function protocolLabel(protocol: string): string {
    return labels[protocol as Protocol] || protocol.toUpperCase()
  }

  function protocolColor(protocol: string) {
    return colors[protocol as Protocol] || 'neutral'
  }

  function formatDate(value?: string | null): string {
    if (!value) return '从未'
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return '未知'
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date)
  }

  function timeAgo(value?: string | null): string {
    if (!value) return '从未'
    const date = new Date(value)
    const diff = Date.now() - date.getTime()
    if (Number.isNaN(diff)) return '未知'
    const minutes = Math.floor(diff / 60000)
    if (minutes < 1) return '刚刚'
    if (minutes < 60) return `${minutes} 分钟前`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours} 小时前`
    const days = Math.floor(hours / 24)
    if (days < 30) return `${days} 天前`
    return formatDate(value)
  }

  function hostPort(server: string, port: number): string {
    return server.includes(':') ? `[${server}]:${port}` : `${server}:${port}`
  }

  return { protocolLabel, protocolColor, formatDate, timeAgo, hostPort }
}
