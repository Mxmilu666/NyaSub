export type Protocol = 'vless' | 'vmess' | 'trojan' | 'ss' | 'hysteria2' | 'tuic' | 'socks5' | 'http' | 'ssh'

export interface RealityOptions {
  public_key: string
  short_id?: string
}

export interface WSOptions {
  path?: string
  headers?: Record<string, string>
  max_early_data?: number
  early_data_header_name?: string
}

export interface GRPCOptions {
  service_name?: string
}

export interface HTTPOptions {
  method?: string
  path?: string[]
  headers?: Record<string, string[]>
}

export interface H2Options {
  host?: string[]
  path?: string
}

export interface NodeConfig {
  server: string
  port: number
  uuid?: string
  alter_id?: number
  cipher?: string
  password?: string
  username?: string
  network?: string
  tls?: boolean
  sni?: string
  alpn?: string[]
  skip_cert_verify?: boolean
  fingerprint?: string
  flow?: string
  encryption?: string
  reality?: RealityOptions
  ws?: WSOptions
  grpc?: GRPCOptions
  http_opts?: HTTPOptions
  h2_opts?: H2Options
  udp?: boolean
  udp_over_tcp?: boolean
  udp_over_tcp_version?: number
  up?: string
  down?: string
  obfs?: string
  obfs_password?: string
  congestion_controller?: string
  udp_relay_mode?: string
  reduce_rtt?: boolean
  disable_sni?: boolean
  plugin?: string
  plugin_opts?: Record<string, unknown>
  private_key?: string
  private_key_passphrase?: string
  host_key?: string[]
  host_key_algorithms?: string[]
  ports?: string
  hop_interval?: string
  extra?: Record<string, unknown>
}

export interface NodeItem {
  id: string
  name: string
  country?: string
  protocol: Protocol
  tags: string[]
  config: NodeConfig
  created_at: string
  updated_at: string
}

export interface NodeSummary {
  id: string
  name: string
  protocol: Protocol
  server: string
  port: number
  tags?: string[]
}

export interface ChainItem {
  id: string
  name: string
  enabled: boolean
  entry_node: NodeSummary
  exit_node: NodeSummary
  warnings: string[] | null
  profile_count: number
  created_at: string
  updated_at: string
}

export interface PolicyGroup {
  name: string
  type: 'select' | 'url-test' | 'fallback' | 'load-balance'
  proxies: string[]
  url?: string
  interval?: number
  tolerance?: number
  lazy?: boolean
  strategy?: string
}

export interface PolicyRule {
  type: string
  payload: string
  target: string
  no_resolve?: boolean
}

export interface TokenInfo {
  id: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
  active: boolean
  url?: string
  xray_url?: string
}

export interface ProfileSummary {
  id: string
  name: string
  description: string
  template?: 'acl4ssr' | ''
  node_count: number
  chain_count: number
  default_exit_type: '' | 'node' | 'chain'
  default_exit_id: string
  force_default_exit: boolean
  token: TokenInfo | null
  created_at: string
  updated_at: string
}

export interface ProfileDetail extends Omit<ProfileSummary, 'token'> {
  node_ids: string[]
  chain_ids: string[]
  nodes: NodeSummary[]
  chains: Array<{
    id: string
    name: string
    enabled: boolean
    entry_node_id: string
    exit_node_id: string
  }>
  groups: PolicyGroup[]
  rules: PolicyRule[]
  dns: Record<string, unknown>
  general: Record<string, unknown>
  tokens: TokenInfo[]
}

export interface AuthUser {
  id: string
  username: string
  created_at: string
}

export interface SessionInfo {
  id: string
  created_at: string
  last_seen_at: string
  expires_at: string
  ip: string
  user_agent: string
  current: boolean
}

export interface DashboardData {
  stats: {
    nodes: number
    chains: number
    enabled_chains: number
    profiles: number
    active_tokens: number
  }
  recent: Array<{
    type: 'profile' | 'node'
    id: string
    name: string
    updated_at: string
  }>
}

export interface AppSettings {
  version: string
  base_url: string
  listen: string
  data_dir: string
  log_level: string
  secure_cookies: boolean
  session_ttl_hours: number
  web_ui: boolean
  backup_format: number
}

export interface ApiErrorBody {
  error: {
    code: string
    message: string
    details?: unknown
  }
}
