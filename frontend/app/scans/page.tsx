'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ScanSearch } from 'lucide-react'
import { Badge, Card, CardBody, CardHeader, DemoBadge, EmptyState, ErrorState, LinkButton, PageHeader, Pagination, Select, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago, formatDate, shortSha } from '@/lib/utils'

export default function ScansPage() {
  const router = useRouter()
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const scans = useQuery<Paged<any>>({
    queryKey: ['scans', status, page],
    queryFn: () => api.get(`/scans${qs({ status, page })}`),
    refetchInterval: (q) => ((q.state.data as any)?.items?.some((s: any) => ['PENDING', 'RUNNING'].includes(s.status)) ? 4000 : 20000),
  })
  const scanners = useQuery<any[]>({ queryKey: ['scanners'], queryFn: () => api.get('/scans/scanners') })
  return (
    <div>
      <PageHeader title="Scans" description="Scanner orchestration runs across all repositories." actions={<LinkButton href="/repositories" variant="outline">Start a scan from a repository</LinkButton>} />
      <Card className="mb-4">
        <CardHeader title="Scanner engines" description="Status is checked live; unavailable scanners are reported as such and never produce synthetic results." />
        <CardBody className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {(scanners.data || Array.from({ length: 4 })).map((s: any, i: number) =>
            s ? (
              <div key={s.name} className="rounded-md border p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{s.name}</span>
                  <StatusBadge status={s.available ? 'ok' : 'unavailable'} />
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{s.category}</p>
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{s.version ? `v${s.version}` : 'binary not found'}</p>
              </div>
            ) : (
              <Skeleton key={i} className="h-20" />
            ),
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader
          title="Scan history"
          action={
            <Select
              value={status}
              onChange={(v) => {
                setStatus(v)
                setPage(1)
              }}
              placeholder="All statuses"
              className="h-8 text-xs"
              options={['PENDING', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED'].map((s) => ({ value: s, label: s.toLowerCase() }))}
            />
          }
        />
        {scans.error ? <ErrorState error={scans.error} className="m-4" /> : null}
        {scans.isLoading ? (
          <Skeleton className="m-4 h-40" />
        ) : scans.data?.items.length ? (
          <>
            <Table>
              <THead>
                <tr>
                  <Th>Repository</Th>
                  <Th>Commit</Th>
                  <Th>Trigger</Th>
                  <Th>Status</Th>
                  <Th>Findings</Th>
                  <Th>Ecosystems</Th>
                  <Th>Started</Th>
                  <Th>Duration</Th>
                </tr>
              </THead>
              <tbody>
                {scans.data.items.map((s) => (
                  <Tr key={s.id} onClick={() => router.push(`/scans/${s.id}`)}>
                    <Td className="font-medium">
                      {s.repository_name} {s.is_demo && <DemoBadge />}
                    </Td>
                    <Td className="font-mono text-xs">
                      {shortSha(s.commit_sha)} <span className="text-muted-foreground">{s.branch}</span>
                    </Td>
                    <Td>
                      <Badge>{s.trigger}</Badge>
                    </Td>
                    <Td>
                      <StatusBadge status={s.status} />
                    </Td>
                    <Td className="tabular text-xs">
                      {s.total_findings}{' '}
                      <span className="text-muted-foreground">
                        ({s.critical_count}C · {s.high_count}H · {s.medium_count}M · {s.low_count}L)
                      </span>
                    </Td>
                    <Td className="text-xs text-muted-foreground">{(s.ecosystems || []).join(', ') || '—'}</Td>
                    <Td className="text-xs" title={formatDate(s.created_at)}>{ago(s.created_at)}</Td>
                    <Td className="tabular text-xs">{s.started_at && s.completed_at ? `${Math.round((+new Date(s.completed_at) - +new Date(s.started_at)) / 1000)}s` : '—'}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            <Pagination page={scans.data.page} pages={scans.data.pages} total={scans.data.total} onPage={setPage} />
          </>
        ) : (
          <EmptyState icon={ScanSearch} title="No scans yet" description="Connect a repository and run a scan." action={<LinkButton href="/repositories">Repositories</LinkButton>} />
        )}
      </Card>
    </div>
  )
}
