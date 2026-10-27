export class ApiError extends Error {
  status: number
  code: string
  details?: unknown

  constructor(message: string, status = 0, code = 'request_failed', details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

interface RequestOptions {
  method?: string
  body?: unknown
  query?: Record<string, unknown>
  headers?: Record<string, string>
}

export function useApi() {
  const csrf = useState<string | null>('nyasub-csrf', () => null)

  async function ensureCsrf(force = false): Promise<string> {
    if (csrf.value && !force) return csrf.value
    const data = await $fetch<{ csrf_token: string }>('/api/auth/csrf')
    csrf.value = data.csrf_token
    return csrf.value
  }

  function normalize(error: unknown): ApiError {
    const err = error as {
      status?: number
      data?: { error?: { code?: string; message?: string; details?: unknown } }
      message?: string
    }
    const body = err?.data?.error
    return new ApiError(
      body?.message || err?.message || 'The request failed.',
      err?.status || 0,
      body?.code || 'request_failed',
      body?.details
    )
  }

  async function request<T>(url: string, options: RequestOptions = {}, retried = false): Promise<T> {
    const method = (options.method || 'GET').toUpperCase() as 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS'
    const headers: Record<string, string> = { ...(options.headers || {}) }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      headers['X-CSRF-Token'] = await ensureCsrf()
    }
    try {
      const fetchJSON = $fetch as unknown as <R>(request: string, opts?: Record<string, unknown>) => Promise<R>
      return await fetchJSON<T>(url, {
        method,
        body: options.body,
        query: options.query,
        headers
      })
    } catch (error) {
      const apiError = normalize(error)
      if (apiError.code === 'csrf_failed' && !retried) {
        await ensureCsrf(true)
        return request<T>(url, options, true)
      }
      if (apiError.status === 401 && !url.startsWith('/api/auth/')) {
        useAuth().clear()
        if (import.meta.client) {
          await navigateTo('/login')
        }
      }
      throw apiError
    }
  }

  async function download(url: string, fallbackName: string): Promise<void> {
    const response = await fetch(url, { credentials: 'same-origin' })
    if (response.status === 401) {
      useAuth().clear()
      if (import.meta.client) await navigateTo('/login')
    }
    if (!response.ok) {
      let message = 'Download failed.'
      try {
        const body = await response.json()
        message = body?.error?.message || message
      } catch {
        // ignore
      }
      throw new ApiError(message, response.status)
    }
    const disposition = response.headers.get('Content-Disposition') || ''
    const match = /filename="?([^";]+)"?/.exec(disposition)
    const filename = match?.[1] || fallbackName
    const blob = await response.blob()
    const objectUrl = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = objectUrl
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(objectUrl)
  }

  return { api: request, ensureCsrf, download }
}
