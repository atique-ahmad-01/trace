'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { FindingsTable, type FindingFilters } from '@/components/findings-table'
import { Button, Card, Input, PageHeader, Select } from '@/components/ui'
import { api } from '@/lib/api'

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function VulnerabilitiesInner() {
  const sp = useSearchParams()
  const router = useRouter()
  const [filters, setFilters] = useState<FindingFilters>({
    q: sp.get('q') || undefined,
    repository_id: sp.get('repository_id') || undefined,
    status: sp.get('status') ?? 'OPEN,IN_PROGRESS',
    severity: sp.get('severity') || undefined,
    sort: 'severity',
  })
  const [page, setPage] = useState(1)
  const [q, setQ] = useState(filters.q || '')
  const repos = useQuery({ queryKey: ['repositories'], queryFn: () => api.get('/repositories?page_size=100') })
  useEffect(() => {
    const nq = sp.get('q') || undefined
    setQ(nq || '')
    setFilters((f) => ({ ...f, q: nq }))
  }, [sp])
  const set = (patch: Partial<FindingFilters>) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(1)
  }
  const sevs = (filters.severity || '').split(',').filter(Boolean)
  return (
    <div>
      <PageHeader title="Vulnerabilities" description="Normalized, deduplicated findings from all scanners, enriched with vulnerability intelligence." />
      <Card className="mb-4 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              set({ q: q || undefined })
              router.replace(q ? `/vulnerabilities?q=${encodeURIComponent(q)}` : '/vulnerabilities')
            }}
          >
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE, package, file, title…" className="h-8 w-60 text-xs" aria-label="Search" />
          </form>
          <div className="flex gap-1" role="group" aria-label="Severity filter">
            {SEVS.map((s) => (
              <button
                key={s}
                onClick={() => set({ severity: (sevs.includes(s) ? sevs.filter((x) => x !== s) : [...sevs, s]).join(',') || undefined })}
                className={`h-8 rounded-md border px-2 text-[11px] font-medium uppercase ${sevs.includes(s) ? 'border-primary bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-accent'}`}
                aria-pressed={sevs.includes(s)}
              >
                {s}
              </button>
            ))}
          </div>
          <Select value={filters.status || ''} onChange={(v) => set({ status: v || undefined })} className="h-8 text-xs" aria-label="Status"
            options={[{ value: 'OPEN,IN_PROGRESS', label: 'Open + in progress' }, { value: '', label: 'Any status' }, ...['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].map((s) => ({ value: s, label: s.toLowerCase().replace('_', ' ') }))]} />
          <Select value={filters.finding_type || ''} onChange={(v) => set({ finding_type: v || undefined })} placeholder="Any type" className="h-8 text-xs" aria-label="Type"
            options={['dependency', 'sast', 'secret', 'misconfig'].map((t) => ({ value: t, label: t }))} />
          <Select value={filters.scanner || ''} onChange={(v) => set({ scanner: v || undefined })} placeholder="Any scanner" className="h-8 text-xs" aria-label="Scanner"
            options={['trivy', 'osv-scanner', 'semgrep', 'gitleaks'].map((t) => ({ value: t, label: t }))} />
          <Select value={filters.repository_id || ''} onChange={(v) => set({ repository_id: v || undefined })} placeholder="All repositories" className="h-8 max-w-[200px] text-xs" aria-label="Repository"
            options={(repos.data?.items || []).map((r: any) => ({ value: r.id, label: r.full_name }))} />
          <Input type="date" value={filters.since?.slice(0, 10) || ''} onChange={(e) => set({ since: e.target.value ? `${e.target.value}T00:00:00` : undefined })} className="h-8 w-36 text-xs" aria-label="First seen since" />
          <Select value={filters.sort || 'severity'} onChange={(v) => set({ sort: v })} className="h-8 text-xs" aria-label="Sort"
            options={[{ value: 'severity', label: 'Sort: severity' }, { value: 'risk', label: 'Sort: AI risk score' }, { value: 'newest', label: 'Sort: newest' }]} />
          {(filters.q || filters.severity || filters.finding_type || filters.scanner || filters.repository_id || filters.since) && (
            <Button variant="ghost" size="sm" onClick={() => { setQ(''); set({ q: undefined, severity: undefined, finding_type: undefined, scanner: undefined, repository_id: undefined, since: undefined }) }}>
              <X /> Clear
            </Button>
          )}
        </div>
      </Card>
      <Card>
        <FindingsTable filters={filters} page={page} onPage={setPage} />
      </Card>
    </div>
  )
}

export default function VulnerabilitiesPage() {
  return (
    <Suspense>
      <VulnerabilitiesInner />
    </Suspense>
  )
}
