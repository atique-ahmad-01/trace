'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Bot } from 'lucide-react'
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState, LinkButton, PageHeader, Pagination, Select, SeverityBadge, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago, titleCase } from '@/lib/utils'

export default function InvestigationsPage() {
  const router = useRouter()
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const catalog = useQuery({ queryKey: ['agent-catalog'], queryFn: () => api.get('/agents/catalog') })
  const list = useQuery<Paged<any>>({
    queryKey: ['investigations', status, page],
    queryFn: () => api.get(`/agents/investigations${qs({ status, page })}`),
    refetchInterval: (q) => ((q.state.data as any)?.items?.some((i: any) => ['queued', 'running'].includes(i.status)) ? 3000 : 20000),
  })
  const c = catalog.data
  return (
    <div>
      <PageHeader title="AI investigations" description="LangGraph multi-agent investigations with persisted traces, evidence and citations." />
      <Card className="mb-4">
        <CardHeader
          title="Agent architecture"
          description={c ? <span>Model provider: <span className="font-mono">{c.provider.provider}:{c.provider.model}</span> — {c.provider.status}</span> : undefined}
        />
        <CardBody>
          {c ? (
            <>
              <div className="mb-4 flex flex-wrap items-center gap-1.5 text-xs">
                {c.graph.map((n: string, i: number) => (
                  <span key={i} className="inline-flex items-center gap-1.5">
                    <span className="rounded border bg-muted/40 px-2 py-1 font-mono">{n}</span>
                    {i < c.graph.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground" />}
                  </span>
                ))}
              </div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {c.agents.map((a: any) => (
                  <div key={a.name} className="rounded-md border p-3">
                    <p className="text-sm font-medium">{a.role}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{a.responsibility}</p>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {a.tools.length ? a.tools.map((t: string) => <Badge key={t}>{t}</Badge>) : <span className="text-[11px] text-muted-foreground">no tools</span>}
                    </div>
                  </div>
                ))}
              </div>
              {c.provider.status !== 'ok' && c.provider.status !== 'configured' && (
                <p className="mt-3 text-xs text-warning">Model provider is {c.provider.status}. Investigations still collect structured evidence but contain no model reasoning until a provider is available.</p>
              )}
            </>
          ) : (
            <Skeleton className="h-32" />
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Investigations" action={<Select value={status} onChange={(v) => { setStatus(v); setPage(1) }} placeholder="All statuses" className="h-8 text-xs" options={['queued', 'running', 'completed', 'partial', 'failed'].map((s) => ({ value: s, label: s }))} />} />
        {list.error ? <ErrorState error={list.error} className="m-4" /> : null}
        {list.isLoading ? (
          <Skeleton className="m-4 h-40" />
        ) : list.data?.items.length ? (
          <>
            <Table>
              <THead>
                <tr>
                  <Th>Finding</Th>
                  <Th>Repository</Th>
                  <Th>Mode</Th>
                  <Th>Model</Th>
                  <Th>Priority</Th>
                  <Th>Status</Th>
                  <Th>Tokens</Th>
                  <Th>Started</Th>
                </tr>
              </THead>
              <tbody>
                {list.data.items.map((i) => (
                  <Tr key={i.id} onClick={() => router.push(`/investigations/${i.id}`)}>
                    <Td className="max-w-[340px]">
                      <span className="flex items-center gap-2">
                        <SeverityBadge severity={i.finding_severity} />
                        <span className="truncate">{i.finding_title}</span>
                      </span>
                    </Td>
                    <Td className="text-xs">{i.repository_name}</Td>
                    <Td className="text-xs">{titleCase(i.mode)}</Td>
                    <Td className="font-mono text-xs">{i.model}</Td>
                    <Td className="font-mono text-xs">{i.priority || '—'}</Td>
                    <Td>
                      <StatusBadge status={i.status} />
                    </Td>
                    <Td className="tabular text-xs">{i.tokens_in + i.tokens_out || '—'}</Td>
                    <Td className="text-xs text-muted-foreground">{ago(i.created_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={setPage} />
          </>
        ) : (
          <EmptyState icon={Bot} title="No investigations yet" description="Open any finding and click “Investigate with AI”, or enable auto-investigation when starting a scan." action={<LinkButton href="/vulnerabilities">Browse findings</LinkButton>} />
        )}
      </Card>
    </div>
  )
}
