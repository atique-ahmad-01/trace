'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { InvestigationResult, InvestigationStatusLine, Timeline } from '@/components/investigation-view'
import { Card, CardBody, CardHeader, ErrorState, PageHeader, SeverityBadge, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/utils'

export default function InvestigationPage({ params }: { params: { id: string } }) {
  const inv = useQuery({
    queryKey: ['investigation', params.id],
    queryFn: () => api.get(`/agents/investigations/${params.id}`),
    refetchInterval: (q) => (['queued', 'running'].includes((q.state.data as any)?.status) ? 2500 : false),
  })
  if (inv.error) return <ErrorState error={inv.error} />
  if (!inv.data) return <Skeleton className="h-96" />
  const d = inv.data
  const running = ['queued', 'running'].includes(d.status)
  return (
    <div>
      <PageHeader
        back={{ href: '/investigations', label: 'Investigations' }}
        title={
          <span className="flex items-center gap-2">
            <SeverityBadge severity={d.finding.severity} />
            <Link href={`/vulnerabilities/${d.finding.id}`} className="hover:text-primary">{d.finding.title}</Link>
          </span>
        }
        description={<span className="flex flex-wrap items-center gap-3"><InvestigationStatusLine inv={d} /> <span className="text-xs">started {formatDate(d.started_at)}</span></span>}
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {running ? <Card><CardBody className="text-sm text-muted-foreground">Agents are running. The timeline updates live.</CardBody></Card> : <InvestigationResult inv={d} />}
          {d.tool_executions.length > 0 && (
            <Card>
              <CardHeader title="MCP tool executions" description="Every agent tool call passes allowlist and per-agent permission checks" />
              <Table>
                <THead>
                  <tr>
                    <Th>Invoked by</Th>
                    <Th>Arguments</Th>
                    <Th>Status</Th>
                    <Th>Duration</Th>
                  </tr>
                </THead>
                <tbody>
                  {d.tool_executions.map((t: any) => (
                    <Tr key={t.id}>
                      <Td className="font-mono text-xs">{t.invoked_by}</Td>
                      <Td className="max-w-[360px] truncate font-mono text-[11px]">{JSON.stringify(t.arguments)}</Td>
                      <Td>
                        <StatusBadge status={t.status} />
                      </Td>
                      <Td className="tabular text-xs">{t.duration_ms ?? '—'} ms</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          )}
        </div>
        <Card className="h-fit">
          <CardHeader title="Agent timeline" description="Decisions, tool calls and evidence — no hidden chain-of-thought" />
          <CardBody>
            <Timeline events={d.events} />
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
