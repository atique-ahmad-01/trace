export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const TOKEN_KEY = 'trace.token'
const ORG_KEY = 'trace.org'

function safeGet(key: string): string | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function safeSet(key: string, value: string | null) {
  try {
    if (value === null) window.localStorage.removeItem(key)
    else window.localStorage.setItem(key, value)
  } catch {
    /* storage unavailable */
  }
}

export const session = {
  token: () => safeGet(TOKEN_KEY),
  setToken: (t: string | null) => safeSet(TOKEN_KEY, t),
  org: () => safeGet(ORG_KEY),
  setOrg: (o: string | null) => safeSet(ORG_KEY, o),
}

export class ApiError extends Error {
  status: number
  detail: unknown
  constructor(status: number, message: string, detail?: unknown) {
    super(message)
    this.status = status
    this.detail = detail
  }
}

function headers(extra?: HeadersInit): HeadersInit {
  const h: Record<string, string> = {}
  const t = session.token()
  if (t) h.Authorization = `Bearer ${t}`
  const o = session.org()
  if (o) h['X-Organization-Id'] = o
  return { ...h, ...(extra as Record<string, string>) }
}

function messageFrom(detail: unknown, fallback: string): string {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((d: any) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
  return fallback
}

async function request<T>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
  const isForm = body instanceof URLSearchParams
  const res = await fetch(`${API_URL}/api/v1${path}`, {
    method,
    headers: headers(body === undefined ? undefined : { 'Content-Type': isForm ? 'application/x-www-form-urlencoded' : 'application/json' }),
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    ...init,
  })
  if (res.status === 401 && typeof window !== 'undefined' && !path.startsWith('/auth/login')) {
    session.setToken(null)
    if (!window.location.pathname.startsWith('/login')) window.location.href = '/login'
  }
  if (!res.ok) {
    let detail: unknown = null
    try {
      detail = (await res.json()).detail
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, messageFrom(detail, `${res.status} ${res.statusText}`), detail)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  get: <T = any>(path: string) => request<T>('GET', path),
  post: <T = any>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T = any>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T = any>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T = any>(path: string) => request<T>('DELETE', path),
}

export async function login(email: string, password: string) {
  const data = await request<{ access_token: string }>('POST', '/auth/login', new URLSearchParams({ username: email, password }))
  session.setToken(data.access_token)
  return data
}

export async function download(path: string, filename: string) {
  const res = await fetch(`${API_URL}/api/v1${path}`, { headers: headers() })
  if (!res.ok) throw new ApiError(res.status, `Download failed (${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function qs(params: Record<string, unknown>): string {
  const p = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0)) p.set(k, Array.isArray(v) ? v.join(',') : String(v))
  })
  const s = p.toString()
  return s ? `?${s}` : ''
}

export type Paged<T> = { items: T[]; total: number; page: number; page_size: number; pages: number }
