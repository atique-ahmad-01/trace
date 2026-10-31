'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, CheckCircle2, FlaskConical, PlugZap, RefreshCw, Save, Trash2 } from 'lucide-react'
import { Badge, Button, Card, CardBody, CardHeader, ErrorState, Input, Label, Notice, Select, Skeleton, Switch } from '@/components/ui'
import { api } from '@/lib/api'
import { integrationsKey, useIntegrations, visibleFields, type Integration } from '@/lib/integrations'
import { ago, cn } from '@/lib/utils'

type TestResult = { ok: boolean; message: string; details?: Record<string, any> }

const STATUS: Record<Integration['status'], { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' | 'primary' }> = {
  ok: { label: 'Connected', tone: 'success' },
  environment: { label: 'From server env', tone: 'primary' },
  unverified: { label: 'Not verified', tone: 'warning' },
  error: { label: 'Verification failed', tone: 'danger' },
  not_configured: { label: 'Not configured', tone: 'neutral' },
}

export function IntegrationsPanel({ isAdmin, setup, returnTo }: { isAdmin: boolean; setup?: string | null; returnTo?: string | null }) {
  const q = useIntegrations()
  if (q.error) return <ErrorState error={q.error} />
  if (!q.data) return <Skeleton className="h-64" />
  const anyEnv = q.data.some((i) => i.source === 'environment')
  return (
    <div className="space-y-4">
      <Notice>
        Each organization connects its own external services here. Secrets are encrypted at rest and never sent back to the browser — only the last 4 characters are shown.
        Saving runs a live check against the service.
        {anyEnv && ' Integrations marked “From server env” use the server’s environment variables until you save your own.'}
      </Notice>
      {q.data.map((i) => (
        <IntegrationCard key={i.kind} item={i} isAdmin={isAdmin} focused={setup === i.kind} returnTo={setup === i.kind ? returnTo : null} />
      ))}
    </div>
  )
}

function initialValues(item: Integration) {
  const v: Record<string, any> = {}
  for (const f of item.fields) if (f.type !== 'secret' && v[f.name] === undefined) v[f.name] = item.config[f.name] ?? f.default ?? (f.type === 'bool' ? false : '')
  return v
}

function IntegrationCard({ item, isAdmin, focused, returnTo }: { item: Integration; isAdmin: boolean; focused: boolean; returnTo?: string | null }) {
  const qc = useQueryClient()
  const router = useRouter()
  const ref = useRef<HTMLDivElement>(null)
  const [editing, setEditing] = useState(focused || (!item.configured && !item.optional))
  const [values, setValues] = useState<Record<string, any>>(() => initialValues(item))
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [test, setTest] = useState<TestResult | null>(null)
  const [justConnected, setJustConnected] = useState(false)

  useEffect(() => {
    if (focused) ref.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [focused])

  const fields = useMemo(() => visibleFields(item.fields, values), [item.fields, values])
  const payload = () => ({
    config: Object.fromEntries(fields.filter((f) => f.type !== 'secret').map((f) => [f.name, values[f.name]])),
    secrets: Object.fromEntries(fields.filter((f) => f.type === 'secret').map((f) => [f.name, secrets[f.name] || ''])),
  })
  const refresh = () => qc.invalidateQueries({ queryKey: integrationsKey })

  const testM = useMutation({ mutationFn: () => api.post<TestResult>(`/integrations/${item.kind}/verify`, payload()), onSuccess: setTest })
  const saveM = useMutation({
    mutationFn: () => api.put<Integration>(`/integrations/${item.kind}`, payload()),
    onSuccess: (saved) => {
      setSecrets({})
      setTest(null)
      qc.setQueryData<Integration[]>(integrationsKey, (old) => old?.map((i) => (i.kind === saved.kind ? saved : i)))
      refresh()
      qc.invalidateQueries({ queryKey: ['system-status'] })
      if (saved.ready) {
        setEditing(false)
        setJustConnected(true)
      }
    },
  })
  const reverifyM = useMutation({ mutationFn: () => api.post<TestResult>(`/integrations/${item.kind}/verify`), onSuccess: (r) => { setTest(r); refresh() } })
  const removeM = useMutation({ mutationFn: () => api.del(`/integrations/${item.kind}`), onSuccess: () => { setValues(initialValues({ ...item, config: {} })); setTest(null); refresh() } })

  const status = STATUS[item.status]
  const models: string[] = test?.details?.available_models || item.details?.available_models || []
  const canSave = fields.every((f) => !f.required || (f.type === 'secret' ? !!secrets[f.name] || item.secrets[f.name]?.set && item.source === 'organization' : f.type === 'bool' || String(values[f.name] ?? '').trim()))

  return (
    <div ref={ref} className="scroll-mt-4">
      <Card className={cn(focused && 'ring-2 ring-primary/50')}>
        <CardHeader
          title={
            <span className="flex flex-wrap items-center gap-2">
              {item.title}
              {item.optional ? <Badge>optional</Badge> : <Badge tone="primary">required</Badge>}
              <Badge tone={status.tone}>{status.label}</Badge>
            </span>
          }
          description={item.description}
          action={isAdmin && !editing ? <Button size="sm" variant="outline" onClick={() => setEditing(true)}><PlugZap /> {item.configured ? 'Edit' : 'Connect'}</Button> : null}
        />
        <CardBody className="space-y-4">
          {justConnected && item.ready && (
            <Notice tone="success" className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-1.5"><CheckCircle2 className="h-4 w-4" /> {item.title} connected and verified. {item.status_message}</span>
              {returnTo && <Button size="sm" onClick={() => router.push(returnTo)}>Continue where you left off <ArrowRight /></Button>}
            </Notice>
          )}

          {!editing && (
            <Summary item={item} />
          )}

          {editing && isAdmin && (
            <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); saveM.mutate() }}>
              <div className="grid gap-3 md:grid-cols-2">
                {fields.map((f) => (
                  <div key={f.name} className={cn(f.type === 'bool' && 'md:col-span-2')}>
                    {f.type === 'bool' ? (
                      <label className="flex items-start gap-3 text-sm">
                        <Switch checked={!!values[f.name]} onChange={(v) => setValues({ ...values, [f.name]: v })} label={f.label} />
                        <span>{f.label}{f.help && <span className="block text-xs text-muted-foreground">{f.help}</span>}</span>
                      </label>
                    ) : (
                      <>
                        <Label htmlFor={`${item.kind}-${f.name}`} hint={f.required ? undefined : 'optional'}>{f.label}</Label>
                        {f.type === 'select' ? (
                          <Select id={`${item.kind}-${f.name}`} value={values[f.name] ?? ''} className="w-full" options={f.options || []}
                                  onChange={(v) => { setValues({ ...values, [f.name]: v }); setTest(null) }} />
                        ) : f.type === 'secret' ? (
                          <Input id={`${item.kind}-${f.name}`} type="password" autoComplete="off" value={secrets[f.name] || ''}
                                 onChange={(e) => setSecrets({ ...secrets, [f.name]: e.target.value })}
                                 placeholder={item.secrets[f.name]?.set && item.source === 'organization' ? `•••• ${item.secrets[f.name].last4 ?? ''} (leave blank to keep)` : f.placeholder} />
                        ) : (
                          <Input id={`${item.kind}-${f.name}`} value={values[f.name] ?? ''} placeholder={f.placeholder} list={f.name === 'model' ? `${item.kind}-models` : undefined}
                                 type={f.type === 'url' ? 'url' : 'text'} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
                        )}
                        {f.help && <p className="mt-1 text-[11px] text-muted-foreground">{f.help}</p>}
                      </>
                    )}
                  </div>
                ))}
              </div>
              {models.length > 0 && <datalist id={`${item.kind}-models`}>{models.map((m) => <option key={m} value={m} />)}</datalist>}

              {test && (
                <Notice tone={test.ok ? 'success' : 'danger'}>
                  {test.ok ? 'Test passed: ' : 'Test failed: '}{test.message}
                  {models.length > 0 && !test.ok && <span className="block">Pick one of the available models from the Model field’s suggestions.</span>}
                </Notice>
              )}
              {saveM.data && !saveM.data.ready && <Notice tone="danger">Saved, but verification failed: {saveM.data.status_message}</Notice>}
              {[testM.error, saveM.error].map((e, i) => (e ? <ErrorState key={i} error={e} /> : null))}

              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="outline" onClick={() => testM.mutate()} loading={testM.isPending} disabled={!canSave}><FlaskConical /> Test connection</Button>
                <Button type="submit" loading={saveM.isPending} disabled={!canSave}><Save /> Save &amp; verify</Button>
                {item.configured && <Button type="button" variant="ghost" onClick={() => { setEditing(false); setTest(null); setValues(initialValues(item)); setSecrets({}) }}>Cancel</Button>}
              </div>
            </form>
          )}

          {!editing && isAdmin && item.configured && (
            <div className="flex flex-wrap gap-2 border-t pt-3">
              <Button size="sm" variant="outline" onClick={() => reverifyM.mutate()} loading={reverifyM.isPending}><RefreshCw /> Re-verify</Button>
              {item.source === 'organization' && (
                <Button size="sm" variant="ghost" onClick={() => removeM.mutate()} loading={removeM.isPending}><Trash2 /> Remove</Button>
              )}
              {reverifyM.data && <span className={cn('self-center text-xs', reverifyM.data.ok ? 'text-success' : 'text-destructive')}>{reverifyM.data.message}</span>}
              {reverifyM.error ? <ErrorState error={reverifyM.error} /> : null}
            </div>
          )}
          {!isAdmin && !item.ready && <Notice tone="warning">Ask an organization admin to connect {item.title}.</Notice>}
        </CardBody>
      </Card>
    </div>
  )
}

function Summary({ item }: { item: Integration }) {
  if (!item.configured) {
    return (
      <p className="text-sm text-muted-foreground">
        Not connected.{item.required_for.length ? ` Needed for ${item.required_for.join(', ').toLowerCase()}.` : ''}
      </p>
    )
  }
  const rows = visibleFields(item.fields, item.config)
  return (
    <div className="space-y-2">
      <dl className="grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[max-content_1fr]">
        {rows.map((f) => (
          <div key={f.name} className="contents">
            <dt className="text-xs text-muted-foreground">{f.label}</dt>
            <dd className="min-w-0 truncate font-mono text-xs">
              {f.type === 'secret'
                ? item.secrets[f.name]?.set ? `•••• ${item.secrets[f.name].last4 ?? '(env)'}` : '—'
                : f.type === 'bool' ? (item.config[f.name] ? 'yes' : 'no')
                : f.type === 'select' ? f.options?.find((o) => o.value === item.config[f.name])?.label ?? item.config[f.name]
                : item.config[f.name] || '—'}
            </dd>
          </div>
        ))}
      </dl>
      {item.status_message && (
        <p className={cn('text-xs', item.status === 'error' ? 'text-destructive' : 'text-muted-foreground')}>
          {item.status_message}{item.verified_at ? ` · checked ${ago(item.verified_at)}` : ''}
        </p>
      )}
    </div>
  )
}
