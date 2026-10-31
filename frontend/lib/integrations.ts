'use client'

import { useQuery } from '@tanstack/react-query'
import { api, INTEGRATION_REQUIRED_EVENT } from '@/lib/api'

export type IntegrationKind = 'model_provider' | 'github' | 'langfuse'

export type IntegrationField = {
  name: string
  label: string
  type: 'select' | 'text' | 'url' | 'secret' | 'bool'
  required?: boolean
  default?: unknown
  placeholder?: string
  help?: string
  options?: { value: string; label: string }[]
  show_if?: Record<string, string[]>
}

export type Integration = {
  kind: IntegrationKind
  title: string
  description: string
  required_for: string[]
  optional: boolean
  fields: IntegrationField[]
  source: 'organization' | 'environment' | null
  configured: boolean
  ready: boolean
  status: 'not_configured' | 'unverified' | 'ok' | 'error' | 'environment'
  status_message: string | null
  config: Record<string, any>
  secrets: Record<string, { set: boolean; last4: string | null }>
  details: Record<string, any>
  verified_at: string | null
  updated_at: string | null
  env_fallback: boolean
}

export type IntegrationRequired = { code: 'integration_required'; integration: IntegrationKind; title: string; message: string; status: string }

export const integrationsKey = ['integrations']

export function useIntegrations() {
  return useQuery<Integration[]>({ queryKey: integrationsKey, queryFn: () => api.get('/integrations'), staleTime: 60_000 })
}

/** Fields that apply to the current form values (resolves `show_if`; first match wins per name). */
export function visibleFields(fields: IntegrationField[], values: Record<string, any>): IntegrationField[] {
  const seen = new Set<string>()
  return fields.filter((f) => {
    const ok = Object.entries(f.show_if || {}).every(([k, allowed]) => allowed.includes(values[k] ?? fields.find((x) => x.name === k)?.default))
    if (!ok || seen.has(f.name)) return false
    seen.add(f.name)
    return true
  })
}

/** Settings link that opens the integration's setup and offers a way back to `returnTo`. */
export function setupHref(kind: IntegrationKind, returnTo?: string) {
  const p = new URLSearchParams({ tab: 'integrations', setup: kind })
  if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//')) p.set('return', returnTo)
  return `/settings?${p.toString()}`
}

export function currentPath() {
  return typeof window === 'undefined' ? '/' : window.location.pathname + window.location.search
}

/** Open the setup prompt (same one a 409 integration_required response opens). */
export function promptSetup(item: Pick<Integration, 'kind' | 'title' | 'status' | 'status_message'>) {
  const detail: IntegrationRequired = {
    code: 'integration_required', integration: item.kind, title: item.title, status: item.status,
    message: item.status === 'error'
      ? `${item.title} failed verification: ${item.status_message || 'unknown error'}. Fix it in Settings → Integrations.`
      : `${item.title} is not configured for this organization. An admin can set it up in Settings → Integrations.`,
  }
  window.dispatchEvent(new CustomEvent(INTEGRATION_REQUIRED_EVENT, { detail }))
}

/**
 * Check an integration before starting an action, so the user is sent to set it up first
 * instead of waiting for the request to fail. The backend enforces the same rule (409).
 */
export function useRequireIntegration(kind: IntegrationKind) {
  const q = useIntegrations()
  const item = q.data?.find((i) => i.kind === kind)
  return {
    item,
    ready: item?.ready ?? true, // unknown yet: let the request through, the API decides
    guard: (action: () => void) => () => {
      if (item && !item.ready) promptSetup(item)
      else action()
    },
  }
}
