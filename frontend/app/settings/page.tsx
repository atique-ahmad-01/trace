'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Trash2, UserPlus } from 'lucide-react'
import { useAuth } from '@/components/providers'
import { Badge, Button, Card, CardBody, CardHeader, EmptyState, ErrorState, Input, KV, Label, Notice, PageHeader, Pagination, Select, Skeleton, StatusBadge, THead, Table, Tabs, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago } from '@/lib/utils'

export default function SettingsPage() {
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const [tab, setTab] = useState('system')
  return (
    <div>
      <PageHeader title="Settings" description="Organization, credentials, service status and audit trail." />
      <Tabs value={tab} onChange={setTab} tabs={[{ value: 'system', label: 'System status' }, { value: 'org', label: 'Organization' }, ...(isAdmin ? [{ value: 'credentials', label: 'Credentials' }, { value: 'audit', label: 'Audit log' }] : [])]} />
      {tab === 'system' && <SystemStatus />}
      {tab === 'org' && <Org isAdmin={isAdmin} />}
      {tab === 'credentials' && <Credentials />}
      {tab === 'audit' && <Audit />}
    </div>
  )
}

function SystemStatus() {
  const q = useQuery({ queryKey: ['system-status'], queryFn: () => api.get('/system/status') })
  if (q.error) return <ErrorState error={q.error} />
  if (!q.data) return <Skeleton className="h-64" />
  const s = q.data
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="Scanners" />
        <CardBody className="space-y-2">
          {s.scanners.map((x: any) => (
            <div key={x.name} className="flex items-center justify-between text-sm">
              <span>{x.name} <span className="text-xs text-muted-foreground">· {x.category}</span></span>
              <span className="flex items-center gap-2 font-mono text-xs">{x.version && `v${x.version}`} <StatusBadge status={x.available ? 'ok' : 'unavailable'} /></span>
            </div>
          ))}
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Model provider" />
        <CardBody>
          <KV items={[
            ['Provider', s.model_provider.provider],
            ['Model', <span key="m" className="font-mono text-xs">{s.model_provider.model || '—'}</span>],
            ['Status', <StatusBadge key="s" status={s.model_provider.status} />],
            ['Hosted', s.model_provider.hosted ? 'yes' : 'no (local)'],
            ['Source code to hosted LLMs', s.source_to_hosted_llm_allowed ? <Badge key="h" tone="warning">allowed</Badge> : 'blocked (default)'],
            ['Available local models', (s.model_provider.available_models || []).join(', ') || '—'],
          ]} />
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="RAG & vector store" />
        <CardBody>
          <KV items={[['Documents', `${s.rag.documents} (${s.rag.embedded_documents} embedded)`], ['Chunks / vectors', `${s.rag.chunks} / ${s.rag.vectors}`], ['Qdrant mode', s.rag.vector_store], ['Embedding model', s.rag.embedding_model], ['Status', s.rag.vector_status]]} />
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Platform" />
        <CardBody>
          <KV items={[
            ['Database', s.database.engine],
            ['Background jobs', `${s.jobs.backend} · running ${s.jobs.running ?? 0} · done ${s.jobs.completed ?? 0} · failed ${s.jobs.failed ?? 0}`],
            ['GitHub App', s.github.app_configured ? 'configured' : 'not configured'],
            ['Webhook secret', s.github.webhook_secret_configured ? 'configured' : 'not configured (webhooks rejected)'],
            ['Intel sync', s.intel_sync.map((x: any) => `${x.source}: ${x.status} ${x.last_synced_at ? ago(x.last_synced_at) : ''}`).join(' · ') || 'not synced yet'],
            ['Langfuse tracing', s.observability.langfuse ? 'enabled' : 'disabled'],
          ]} />
        </CardBody>
      </Card>
    </div>
  )
}

function Org({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('member')
  const q = useQuery({ queryKey: ['org'], queryFn: () => api.get('/organizations/current') })
  const add = useMutation({ mutationFn: () => api.post('/organizations/current/members', { email, role }), onSuccess: () => { setEmail(''); qc.invalidateQueries({ queryKey: ['org'] }) } })
  if (!q.data) return <Skeleton className="h-48" />
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title={q.data.organization.name} description={`slug: ${q.data.organization.slug} · your role: ${q.data.role}`} />
        <Table>
          <THead><tr><Th>Member</Th><Th>Role</Th></tr></THead>
          <tbody>{q.data.members.map((m: any) => <Tr key={m.user_id}><Td>{m.email}</Td><Td><Badge>{m.role}</Badge></Td></Tr>)}</tbody>
        </Table>
        {isAdmin && (
          <CardBody className="border-t">
            <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); add.mutate() }}>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="registered user email" className="max-w-xs" type="email" required />
              <Select value={role} onChange={setRole} options={['viewer', 'member', 'admin'].map((r) => ({ value: r, label: r }))} />
              <Button type="submit" loading={add.isPending}><UserPlus /> Add</Button>
            </form>
            {add.error ? <ErrorState error={add.error} className="mt-2" /> : null}
          </CardBody>
        )}
      </Card>
      <Card>
        <CardHeader title="GitHub App installations" />
        {q.data.github_installations.length ? (
          <ul className="divide-y text-sm">{q.data.github_installations.map((i: any) => <li key={i.id} className="px-5 py-2.5">{i.account_login} <span className="text-xs text-muted-foreground">· {i.repository_selection} · {i.suspended ? 'suspended' : 'active'}</span></li>)}</ul>
        ) : <EmptyState title="No installations linked" description="Configure GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_PATH and GITHUB_APP_SLUG, install the app, then link the installation id via POST /api/v1/repositories/github/installations." />}
      </Card>
    </div>
  )
}

function Credentials() {
  const qc = useQueryClient()
  const [value, setValue] = useState('')
  const q = useQuery<any[]>({ queryKey: ['credentials'], queryFn: () => api.get('/organizations/current/credentials') })
  const save = useMutation({ mutationFn: () => api.put('/organizations/current/credentials', { kind: 'github_token', name: 'default', value }), onSuccess: () => { setValue(''); qc.invalidateQueries({ queryKey: ['credentials'] }) } })
  const del = useMutation({ mutationFn: (id: string) => api.del(`/organizations/current/credentials/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }) })
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader title="GitHub token" description="Used for private repository access, branch listing and pull requests when no GitHub App installation is linked." />
        <CardBody className="space-y-3">
          <Notice>Tokens are encrypted at rest (Fernet) and never returned by the API — only the last 4 characters are shown. Use a fine-grained token with Contents (read/write) and Pull requests (write) on selected repositories.</Notice>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
            <div className="flex-1"><Label>Token</Label><Input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} placeholder="github_pat_…" /></div>
            <Button type="submit" className="self-end" loading={save.isPending} disabled={value.length < 8}><KeyRound /> Save</Button>
          </form>
          {save.error ? <ErrorState error={save.error} /> : null}
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Stored credentials" />
        {q.data?.length ? (
          <ul className="divide-y text-sm">
            {q.data.map((c) => (
              <li key={c.id} className="flex items-center justify-between px-5 py-2.5">
                <span>{c.kind} / {c.name} <span className="font-mono text-xs text-muted-foreground">••••{c.last4}</span> <span className="text-xs text-muted-foreground">· updated {ago(c.updated_at)}</span></span>
                <Button size="icon" variant="ghost" aria-label="Delete credential" onClick={() => del.mutate(c.id)}><Trash2 /></Button>
              </li>
            ))}
          </ul>
        ) : <EmptyState title="No credentials stored" />}
      </Card>
    </div>
  )
}

function Audit() {
  const [page, setPage] = useState(1)
  const [action, setAction] = useState('')
  const q = useQuery<Paged<any>>({ queryKey: ['audit', page, action], queryFn: () => api.get(`/organizations/current/audit${qs({ page, action })}`) })
  return (
    <Card>
      <CardHeader title="Audit trail" description="Every security-sensitive action: logins, scans, status changes, approvals, PRs, tool permissions and executions." action={<Select value={action} onChange={(v) => { setAction(v); setPage(1) }} placeholder="All actions" className="h-8 text-xs" options={['auth', 'scan', 'finding', 'investigation', 'remediation', 'mcp', 'credential', 'repository', 'report', 'webhook'].map((a) => ({ value: a, label: a }))} />} />
      {q.data?.items.length ? (
        <>
          <Table>
            <THead><tr><Th>Time</Th><Th>Actor</Th><Th>Action</Th><Th>Resource</Th><Th>Details</Th></tr></THead>
            <tbody>
              {q.data.items.map((a) => (
                <Tr key={a.id}>
                  <Td className="whitespace-nowrap text-xs">{ago(a.created_at)}</Td>
                  <Td className="text-xs">{a.actor}</Td>
                  <Td className="font-mono text-xs">{a.action}</Td>
                  <Td className="font-mono text-[11px] text-muted-foreground">{a.resource_type ? `${a.resource_type}:${(a.resource_id || '').slice(0, 8)}` : '—'}</Td>
                  <Td className="max-w-[360px] truncate font-mono text-[11px] text-muted-foreground" title={JSON.stringify(a.details)}>{JSON.stringify(a.details)}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={q.data.page} pages={q.data.pages} total={q.data.total} onPage={setPage} />
        </>
      ) : q.isLoading ? <Skeleton className="m-4 h-40" /> : <EmptyState title="No audit events" />}
    </Card>
  )
}
