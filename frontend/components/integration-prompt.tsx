'use client'

import { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, PlugZap, X } from 'lucide-react'
import { useAuth } from '@/components/providers'
import { Button, LinkButton, Modal, Notice } from '@/components/ui'
import { INTEGRATION_REQUIRED_EVENT } from '@/lib/api'
import { currentPath, integrationsKey, setupHref, useIntegrations, type IntegrationRequired } from '@/lib/integrations'

/** Global "set this up first" prompt, opened by any 409 integration_required response or by promptSetup(). */
export function IntegrationPrompt() {
  const router = useRouter()
  const qc = useQueryClient()
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const [req, setReq] = useState<IntegrationRequired | null>(null)
  const [returnTo, setReturnTo] = useState('/')
  const items = useIntegrations().data

  useEffect(() => {
    const onRequired = (e: Event) => {
      setReq((e as CustomEvent<IntegrationRequired>).detail)
      setReturnTo(currentPath())
      qc.invalidateQueries({ queryKey: integrationsKey }) // status may have changed since it was cached
    }
    window.addEventListener(INTEGRATION_REQUIRED_EVENT, onRequired)
    return () => window.removeEventListener(INTEGRATION_REQUIRED_EVENT, onRequired)
  }, [qc])

  const item = items?.find((i) => i.kind === req?.integration)
  const close = () => setReq(null)
  return (
    <Modal
      open={!!req}
      onClose={close}
      title={req?.status === 'error' ? `Fix ${req.title} first` : `Set up ${req?.title ?? 'integration'} first`}
      footer={
        <>
          <Button variant="outline" onClick={close}>Not now</Button>
          {isAdmin && req && (
            <Button onClick={() => { close(); router.push(setupHref(req.integration, returnTo)) }}>
              <PlugZap /> {req.status === 'error' ? 'Open settings' : 'Set up now'}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <p>{req?.message}</p>
        {item?.required_for.length ? (
          <p className="text-xs text-muted-foreground">Needed for: {item.required_for.join(', ')}.</p>
        ) : null}
        {isAdmin ? (
          <p className="text-xs text-muted-foreground">You will be brought back here once it is connected and verified.</p>
        ) : (
          <Notice tone="warning">Only organization admins can configure integrations. Ask an admin to set it up in Settings → Integrations.</Notice>
        )}
      </div>
    </Modal>
  )
}

/** Slim banner while a required integration (the model provider) is missing or failing. */
export function IntegrationBanner() {
  const pathname = usePathname()
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const items = useIntegrations().data
  const [hidden, setHidden] = useState(false)
  const missing = items?.filter((i) => !i.optional && !i.ready) ?? []
  if (hidden || !missing.length || pathname.startsWith('/settings')) return null
  const m = missing[0]
  return (
    <div className="flex items-center gap-3 border-b border-warning/30 bg-warning/5 px-4 py-2 text-xs text-warning md:px-8">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="min-w-0 flex-1">
        {m.status === 'error' ? `${m.title} failed verification — ` : `${m.title} not connected — `}
        {m.required_for.join(', ').toLowerCase()} are unavailable until {isAdmin ? 'you connect one' : 'an admin connects one'}.
      </span>
      {isAdmin && <LinkButton href={setupHref(m.kind, pathname)} size="sm" variant="outline" className="h-7">Set up</LinkButton>}
      <button onClick={() => setHidden(true)} className="rounded p-1 hover:bg-warning/10" aria-label="Dismiss"><X className="h-3.5 w-3.5" /></button>
    </div>
  )
}
