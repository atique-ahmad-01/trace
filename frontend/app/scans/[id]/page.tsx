'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FindingsTable } from '@/components/findings-table'
import { Card, CardBody, CardHeader, DemoBadge, ErrorState, KV, Notice, PageHeader, Skeleton, Stat, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api } from '@/lib/api'
import { SEV_VAR, formatDate, shortSha } from '@/lib/utils'

export default function ScanPage({ params }: { params: { id: string } }) {
  const [page, setPage] = useState(1)
  const scan = useQuery({
    queryKey: ['scan', params.id],
    queryFn: () => api.get(`/scans/${params.id}`),
    refetchInterval: (q) => (['PENDING', 'RUNNING'].includes((q.state.data as any)?.status) ? 2500 : false),
  })
  const s = scan.data
  if (scan.error) return <ErrorState error={scan.error} />
  if (!s) return <Skeleton className="h-96" />
  const done = ['COMPLETED', 'PARTIAL'].includes(s.status)
  return (
    <div>
      <PageHeader
        back={{ href: '/scans', label: 'Scans' }}
        title={
          <span className="inline-flex items-center gap-2">
            Scan of {s.repository_name} {s.is_demo && <DemoBadge />} <StatusBadge status={s.status} />
          </span>
        }
        description={
          <span className="font-mono text-xs">
            {shortSha(s.commit_sha)} · {s.branch} · {s.trigger} · {formatDate(s.created_at)}
          </span>
        }
      />
      {s.error_message && <ErrorState error={s.error_message} className="mb-4" />}
      {s.status === 'PARTIAL' && <Notice tone="warning" className="mb-4">Some scanners did not complete. Results include only scanners that finished; see execution details below.</Notice>}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat label="Unique findings" value={s.total_findings} sub={`${s.new_findings} new`} />
        <Stat label="Critical" value={s.critical_count} tone={SEV_VAR.CRITICAL} />
        <Stat label="High" value={s.high_count} tone={SEV_VAR.HIGH} />
        <Stat label="Medium" value={s.medium_count} tone={SEV_VAR.MEDIUM} />
        <Stat label="Low" value={s.low_count} tone={SEV_VAR.LOW} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader title="Scanner executions" description="Each scanner runs as a sandboxed subprocess (no shell, minimal env, time & resource limits)" />
          <Table>
            <THead>
              <tr>
                <Th>Scanner</Th>
                <Th>Version</Th>
                <Th>Status</Th>
                <Th>Raw findings</Th>
                <Th>Duration</Th>
                <Th>Detail</Th>
              </tr>
            </THead>
            <tbody>
              {s.executions.map((e: any) => (
                <Tr key={e.id}>
                  <Td className="font-medium">{e.scanner_name}</Td>
                  <Td className="font-mono text-xs">{e.scanner_version || '—'}</Td>
                  <Td>
                    <StatusBadge status={e.status} />
                  </Td>
                  <Td className="tabular">{e.status === 'completed' ? e.findings_count : '—'}</Td>
                  <Td className="tabular text-xs">{e.duration_seconds ? `${e.duration_seconds}s` : '—'}</Td>
                  <Td className="max-w-[260px] text-xs text-muted-foreground">
                    <span className="line-clamp-2" title={e.error_message || (e.command || []).join(' ')}>
                      {e.error_message || <span className="font-mono">{(e.command || []).slice(0, 4).join(' ')}</span>}
                    </span>
                  </Td>
                </Tr>
              ))}
              {!s.executions.length && (
                <Tr>
                  <Td colSpan={6} className="text-center text-xs text-muted-foreground">
                    Waiting for scanners…
                  </Td>
                </Tr>
              )}
            </tbody>
          </Table>
          <CardBody className="border-t">
            <KV items={[['Ecosystems', (s.ecosystems || []).join(', ') || '—'], ['Requested scanners', (s.scanners_requested || []).join(', ') || 'all applicable'], ['Repository', <Link key="r" className="text-primary hover:underline" href={`/repositories/${s.repository_id}`}>{s.repository_name}</Link>]]} />
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Execution log" />
          <CardBody className="scrollbar-thin max-h-[360px] space-y-1 overflow-y-auto font-mono text-[11px]">
            {(s.log || []).map((l: any, i: number) => (
              <div key={i} className={l.level === 'error' ? 'text-destructive' : l.level === 'warning' ? 'text-warning' : 'text-muted-foreground'}>
                <span className="opacity-60">{l.t.slice(11, 19)}</span> {l.msg}
              </div>
            ))}
          </CardBody>
        </Card>
      </div>
      {done && (
        <Card className="mt-4">
          <CardHeader title="Current findings for this repository" description="Deduplicated across scans; resolved findings are excluded by default status filters on the Vulnerabilities page" />
          <FindingsTable filters={{ repository_id: s.repository_id }} page={page} onPage={setPage} showRepo={false} />
        </Card>
      )}
    </div>
  )
}
