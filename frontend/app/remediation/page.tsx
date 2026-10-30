'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Wrench } from 'lucide-react'
import { Badge, Card, CardHeader, EmptyState, ErrorState, LinkButton, PageHeader, Pagination, Select, SeverityBadge, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago, titleCase } from '@/lib/utils'

export default function RemediationPage() {
  const router = useRouter()
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const list = useQuery<Paged<any>>({ queryKey: ['proposals', status, page], queryFn: () => api.get(`/remediation/proposals${qs({ status, page })}`) })
  return (
    <div>
      <PageHeader title="Remediation" description="Agent-proposed fixes. Nothing is applied or opened as a pull request without explicit human approval; nothing is merged automatically." />
      <Card>
        <CardHeader title="Proposals" action={<Select value={status} onChange={(v) => { setStatus(v); setPage(1) }} placeholder="All statuses" className="h-8 text-xs" options={['proposed', 'approved', 'rejected', 'verified', 'verification_failed', 'pr_opened'].map((s) => ({ value: s, label: titleCase(s) }))} />} />
        {list.error ? <ErrorState error={list.error} className="m-4" /> : null}
        {list.isLoading ? <Skeleton className="m-4 h-40" /> : list.data?.items.length ? (
          <>
            <Table>
              <THead><tr><Th>Proposal</Th><Th>Finding</Th><Th>Repository</Th><Th>Type</Th><Th>Evidence</Th><Th>Status</Th><Th>Created</Th></tr></THead>
              <tbody>
                {list.data.items.map((p) => (
                  <Tr key={p.id} onClick={() => router.push(`/remediation/${p.id}`)}>
                    <Td className="max-w-[300px] truncate font-medium">{p.title}</Td>
                    <Td className="max-w-[280px]"><span className="flex items-center gap-2"><SeverityBadge severity={p.finding_severity} /><span className="truncate text-xs">{p.finding_title}</span></span></Td>
                    <Td className="text-xs">{p.repository_name}</Td>
                    <Td><Badge>{titleCase(p.remediation_type)}{p.has_patch ? ' · patch' : ''}</Badge></Td>
                    <Td>{p.evidence_sufficient ? <Badge tone="success">sufficient</Badge> : <Badge tone="warning">insufficient</Badge>}</Td>
                    <Td><StatusBadge status={p.status} /></Td>
                    <Td className="text-xs text-muted-foreground">{ago(p.created_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={setPage} />
          </>
        ) : <EmptyState icon={Wrench} title="No remediation proposals" description="Proposals are created by the remediation agent during AI investigations." action={<LinkButton href="/vulnerabilities">Investigate a finding</LinkButton>} />}
      </Card>
    </div>
  )
}
