'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Play, ScanSearch, ShieldCheck, Trash2 } from 'lucide-react'
import { FindingsTable } from '@/components/findings-table'
import { useAuth } from '@/components/providers'
import { VulnerabilityTrends } from '@/components/dashboard/vulnerability-trends'
import { Badge, Button, Card, CardBody, CardHeader, Checkbox, DemoBadge, EmptyState, ErrorState, ExtLink, KV, Modal, PageHeader, Select, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { ApiError, api, download } from '@/lib/api'
import { ExternalLink, LOCAL_SETUP_URL, REPO_URL } from '@/components/project-links'
import { useRequireIntegration } from '@/lib/integrations'
import { ago, formatDate, shortSha } from '@/lib/utils'

const SCANNERS = ['trivy', 'osv-scanner', 'semgrep', 'gitleaks']

export default function RepositoryPage({ params }: { params: { id: string } }) {
  const qc = useQueryClient()
  const router = useRouter()
  const { role } = useAuth()
  const [page, setPage] = useState(1)
  const [scanOpen, setScanOpen] = useState(false)
  const repo = useQuery({
    queryKey: ['repository', params.id],
    queryFn: () => api.get(`/repositories/${params.id}`),
    refetchInterval: (q) => ((q.state.data as any)?.scans?.some((s: any) => ['PENDING', 'RUNNING'].includes(s.status)) ? 4000 : false),
  })
  const del = useMutation({
    mutationFn: () => api.del(`/repositories/${params.id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['repositories'] })
      router.push('/repositories')
    },
  })
  const r = repo.data
  if (repo.error) return <ErrorState error={repo.error} />
  if (!r) return <Skeleton className="h-96" />
  const running = r.scans.some((s: any) => ['PENDING', 'RUNNING'].includes(s.status))
  return (
    <div>
      <PageHeader
        back={{ href: '/repositories', label: 'Repositories' }}
        title={
          <span className="inline-flex items-center gap-2">
            {r.full_name} {r.is_demo && <DemoBadge />}
          </span>
        }
        description={r.description}
        actions={
          <>
            <Button variant="outline" onClick={() => download(`/reports/repository/${r.id}?format=pdf`, `trace-${r.name}.pdf`)}>
              <Download /> PDF report
            </Button>
            {role && ['admin', 'owner'].includes(role) && (
              <Button variant="ghost" size="icon" aria-label="Delete repository" onClick={() => confirm(`Disconnect ${r.full_name}? Scan history and findings will be deleted.`) && del.mutate()}>
                <Trash2 />
              </Button>
            )}
            <Button onClick={() => setScanOpen(true)} disabled={running}>
              <Play /> {running ? 'Scan running…' : 'Run scan'}
            </Button>
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Repository" />
          <CardBody>
            <KV
              items={[
                ['Provider', <Badge key="p">{r.provider}</Badge>],
                ['Default branch', <span key="b" className="font-mono text-xs">{r.default_branch}</span>],
                ['Ecosystems', (r.ecosystems || []).join(', ') || '—'],
                ['Last scanned', r.last_scanned_at ? `${ago(r.last_scanned_at)}` : 'never'],
                ['Last commit', <span key="c" className="font-mono text-xs">{shortSha(r.last_scanned_commit)}</span>],
                ['Security score', <span key="s" className="tabular font-semibold">{r.security_score ?? '—'}</span>],
                ['Open findings', r.open_findings],
                ['URL', r.html_url ? <ExtLink key="u" href={r.html_url}>{r.html_url}</ExtLink> : '—'],
              ]}
            />
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Findings per scan" description="Severity breakdown of each completed scan" />
          <CardBody>
            {r.trend.length > 1 ? (
              <VulnerabilityTrends series={r.trend.map((t: any) => ({ date: t.date.slice(0, 16).replace('T', ' '), CRITICAL: t.critical, HIGH: t.high, MEDIUM: t.medium, LOW: t.low }))} height={220} />
            ) : (
              <EmptyState icon={ScanSearch} title={r.trend.length ? 'One completed scan so far' : 'No completed scans'} description="Run more scans to see the trend." />
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Scan history" />
        {r.scans.length ? (
          <Table>
            <THead>
              <tr>
                <Th>Started</Th>
                <Th>Commit</Th>
                <Th>Trigger</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>New</Th>
              </tr>
            </THead>
            <tbody>
              {r.scans.map((s: any) => (
                <Tr key={s.id} onClick={() => router.push(`/scans/${s.id}`)}>
                  <Td className="text-xs">{formatDate(s.created_at)}</Td>
                  <Td className="font-mono text-xs">
                    {shortSha(s.commit_sha)} <span className="text-muted-foreground">{s.branch}</span>
                  </Td>
                  <Td className="text-xs">{s.trigger}</Td>
                  <Td>
                    <StatusBadge status={s.status} />
                  </Td>
                  <Td className="tabular text-xs">
                    {s.total_findings} <span className="text-muted-foreground">({s.critical_count}C / {s.high_count}H)</span>
                  </Td>
                  <Td className="tabular text-xs">{s.new_findings}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <EmptyState title="No scans yet" action={<Button onClick={() => setScanOpen(true)}>Run first scan</Button>} />
        )}
      </Card>

      <Card className="mt-4">
        <CardHeader title="Open findings" action={<Link href={`/vulnerabilities?repository_id=${r.id}`} className="text-xs text-primary hover:underline">Open in Vulnerabilities</Link>} />
        <FindingsTable filters={{ repository_id: r.id, status: 'OPEN,IN_PROGRESS' }} page={page} onPage={setPage} showRepo={false} />
      </Card>
      <ScanModal open={scanOpen} onClose={() => setScanOpen(false)} repo={r} />
    </div>
  )
}

function ScanModal({ open, onClose, repo }: { open: boolean; onClose: () => void; repo: any }) {
  const qc = useQueryClient()
  const router = useRouter()
  const [scanners, setScanners] = useState<string[]>(SCANNERS)
  const [branch, setBranch] = useState('')
  const [auto, setAuto] = useState(false)
  const llm = useRequireIntegration('model_provider')
  const branches = useQuery<any[]>({ queryKey: ['branches', repo.id], queryFn: () => api.get(`/repositories/${repo.id}/branches`), enabled: open && repo.provider === 'github' })
  const status = useQuery<any[]>({ queryKey: ['scanners'], queryFn: () => api.get('/scans/scanners'), enabled: open })
  const run = useMutation({
    mutationFn: () => api.post('/scans', { repository_id: repo.id, branch: branch || undefined, scanners, auto_investigate: auto }),
    onSuccess: (scan: any) => {
      qc.invalidateQueries({ queryKey: ['repository', repo.id] })
      onClose()
      router.push(`/scans/${scan.id}`)
    },
  })
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Scan ${repo.full_name}`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={auto ? llm.guard(() => run.mutate()) : () => run.mutate()} loading={run.isPending} disabled={!scanners.length}>
            <Play /> Start scan
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {repo.provider === 'github' && (
          <div>
            <p className="mb-1.5 text-xs font-medium text-muted-foreground">Branch</p>
            <Select value={branch} onChange={setBranch} placeholder={`${repo.default_branch} (default)`} className="w-full" options={(branches.data || []).map((b) => ({ value: b.name, label: `${b.name} · ${b.sha.slice(0, 7)}` }))} />
          </div>
        )}
        <div>
          <p className="mb-2 text-xs font-medium text-muted-foreground">Scanners</p>
          <div className="grid grid-cols-2 gap-2">
            {SCANNERS.map((s) => {
              const st = status.data?.find((x) => x.name === s)
              return (
                <div key={s} className="rounded-md border p-2.5">
                  <Checkbox checked={scanners.includes(s)} onChange={(v) => setScanners(v ? [...scanners, s] : scanners.filter((x) => x !== s))} label={<span className="font-medium">{s}</span>} />
                  <p className="mt-1 pl-6 text-[11px] text-muted-foreground">{st ? (st.available ? `${st.category} · v${st.version}` : 'unavailable — will be reported, not faked') : '…'}</p>
                </div>
              )
            })}
          </div>
        </div>
        <Checkbox checked={auto} onChange={setAuto} label={<span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-4 w-4" /> Auto-investigate top critical/high findings with AI agents</span>} />
        {run.error ? <ErrorState error={run.error} /> : null}
        {run.error instanceof ApiError && run.error.status === 503 ? (
          <p className="text-xs text-muted-foreground">
            TRACE is open source: run it with all four scanners on your machine.{' '}
            <ExternalLink href={LOCAL_SETUP_URL} className="text-primary hover:underline">Local setup guide</ExternalLink>
            {' · '}
            <ExternalLink href={REPO_URL} className="text-primary hover:underline">GitHub</ExternalLink>
          </p>
        ) : null}
      </div>
    </Modal>
  )
}
