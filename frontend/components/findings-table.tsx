'use client'

import { useRouter } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { DemoBadge, EmptyState, ErrorState, Pagination, SeverityBadge, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago } from '@/lib/utils'

export type FindingFilters = {
  severity?: string
  status?: string
  repository_id?: string
  scanner?: string
  finding_type?: string
  q?: string
  since?: string
  sort?: string
  demo?: boolean
}

export function FindingsTable({ filters, page, onPage, showRepo = true }: { filters: FindingFilters; page: number; onPage: (p: number) => void; showRepo?: boolean }) {
  const router = useRouter()
  const { data, isLoading, error } = useQuery<Paged<any>>({
    queryKey: ['findings', filters, page],
    queryFn: () => api.get(`/findings${qs({ ...filters, page, page_size: 25 })}`),
    placeholderData: (prev) => prev,
  })
  if (error) return <ErrorState error={error} className="m-4" />
  if (isLoading) return <div className="space-y-2 p-4">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-9" />)}</div>
  if (!data?.items.length) return <EmptyState icon={ShieldCheck} title="No findings match these filters" description="Adjust filters, or run a scan to generate findings." />
  return (
    <>
      <Table>
        <THead>
          <tr>
            <Th>Severity</Th>
            <Th>Finding</Th>
            {showRepo && <Th>Repository</Th>}
            <Th>Location / package</Th>
            <Th>Detected by</Th>
            <Th>Priority</Th>
            <Th>Status</Th>
            <Th>First seen</Th>
          </tr>
        </THead>
        <tbody>
          {data.items.map((f) => (
            <Tr key={f.id} onClick={() => router.push(`/vulnerabilities/${f.id}`)}>
              <Td>
                <SeverityBadge severity={f.severity} />
              </Td>
              <Td className="max-w-[360px]">
                <p className="truncate font-medium">{f.title}</p>
                <p className="truncate text-[11px] text-muted-foreground">
                  {[f.vuln_id, f.cvss_score ? `CVSS ${f.cvss_score}` : null, f.cwe_ids?.[0], f.finding_type].filter(Boolean).join(' · ')}
                </p>
              </Td>
              {showRepo && (
                <Td className="whitespace-nowrap text-xs">
                  <span className="inline-flex items-center gap-1.5">
                    {f.repository_name} {f.is_demo && <DemoBadge />}
                  </span>
                </Td>
              )}
              <Td className="max-w-[260px] font-mono text-xs">
                {f.package_name ? (
                  <span className="block truncate">
                    {f.package_name}@{f.installed_version}
                    {f.fixed_version && <span className="text-success"> → {f.fixed_version.split(',')[0]}</span>}
                  </span>
                ) : (
                  <span className="block truncate">
                    {f.file_path}
                    {f.start_line ? `:${f.start_line}` : ''}
                  </span>
                )}
              </Td>
              <Td className="whitespace-nowrap text-xs text-muted-foreground">{(f.detected_by?.length ? f.detected_by : [f.scanner_name]).join(', ')}</Td>
              <Td className="font-mono text-xs">{f.priority || '—'}</Td>
              <Td>
                <StatusBadge status={f.status} />
              </Td>
              <Td className="whitespace-nowrap text-xs text-muted-foreground">{ago(f.first_seen_at)}</Td>
            </Tr>
          ))}
        </tbody>
      </Table>
      <Pagination page={data.page} pages={data.pages} total={data.total} onPage={onPage} />
    </>
  )
}
