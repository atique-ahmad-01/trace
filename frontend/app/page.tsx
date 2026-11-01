'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertOctagon, Bot, FolderGit2, ScanSearch, ShieldAlert, Wrench } from 'lucide-react'
import { MostVulnerableRepos } from '@/components/dashboard/most-vulnerable-repos'
import { PostureGauge, SeverityBars } from '@/components/dashboard/metrics'
import { RecentFindings } from '@/components/dashboard/recent-findings'
import { RecentScans } from '@/components/dashboard/recent-scans'
import { VulnerabilityTrends } from '@/components/dashboard/vulnerability-trends'
import { Card, CardBody, CardHeader, EmptyState, ErrorState, LinkButton, Notice, PageHeader, Select, Skeleton, Stat, StatusBadge } from '@/components/ui'
import { api, qs } from '@/lib/api'
import { SEV_VAR, ago, fmtNum, titleCase } from '@/lib/utils'

export default function OverviewPage() {
  const [scope, setScope] = useState('')
  const [range, setRange] = useState('30d')
  const demo = scope === '' ? undefined : scope === 'demo'
  const intraday = range.endsWith('h')
  const span = intraday ? { hours: parseInt(range) } : { days: parseInt(range) }
  const summary = useQuery({ queryKey: ['dashboard', scope], queryFn: () => api.get(`/dashboard/summary${qs({ demo })}`), refetchInterval: 15_000 })
  const trends = useQuery({
    queryKey: ['trends', scope, range],
    queryFn: () => api.get(`/dashboard/trends${qs({ demo, ...span })}`),
    refetchInterval: intraday ? 60_000 : undefined,
  })
  const d = summary.data

  return (
    <div>
      <PageHeader
        title="Security overview"
        description="Posture across all connected repositories, computed from stored scan results."
        actions={
          <Select
            value={scope}
            onChange={setScope}
            aria-label="Data scope"
            options={[
              { value: '', label: 'All data' },
              { value: 'real', label: 'Real scans only' },
              { value: 'demo', label: 'Demo data only' },
            ]}
          />
        }
      />
      {summary.error ? <ErrorState error={summary.error} /> : null}
      {d?.data_scope.demo_data_present && scope !== 'real' && (
        <Notice tone="warning" className="mb-4">
          Includes demo data: real scanner results from local test fixtures (repositories marked <span className="font-medium">Demo</span>), such as the bundled intentionally vulnerable app. Use “Real scans only” to exclude them.
        </Notice>
      )}

      {!summary.isLoading && d && d.total_repositories === 0 ? (
        <Card>
          <EmptyState
            icon={FolderGit2}
            title="Connect your first repository"
            description="TRACE scans repositories with Trivy, OSV-Scanner, Semgrep and Gitleaks, then enriches findings with NVD, OSV, GHSA and CISA KEV intelligence."
            action={<LinkButton href="/repositories">Connect repository</LinkButton>}
          />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
            {summary.isLoading || !d ? (
              Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-[92px]" />)
            ) : (
              <>
                <Stat label="Repositories" value={fmtNum(d.total_repositories)} icon={FolderGit2} sub={`${fmtNum(d.total_scans)} scans`} />
                <Stat label="Open findings" value={fmtNum(d.open_findings)} icon={ShieldAlert} sub={`${d.severity_counts.INFO ? `${fmtNum(d.severity_counts.INFO)} info · ` : ''}${fmtNum(d.resolved_findings)} resolved`} />
                <Stat label="Critical" value={fmtNum(d.severity_counts.CRITICAL)} tone={SEV_VAR.CRITICAL} icon={AlertOctagon} sub="open" />
                <Stat label="High" value={fmtNum(d.severity_counts.HIGH)} tone={SEV_VAR.HIGH} sub="open" />
                <Stat label="Medium" value={fmtNum(d.severity_counts.MEDIUM)} tone={SEV_VAR.MEDIUM} sub="open" />
                <Stat label="Low" value={fmtNum(d.severity_counts.LOW)} tone={SEV_VAR.LOW} sub="open" />
              </>
            )}
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader
                title="Open findings over time"
                description="Reconstructed from first-seen and resolved timestamps"
                action={
                  <Select
                    value={range}
                    onChange={setRange}
                    aria-label="Range"
                    options={[
                      { value: '5h', label: '5 hours' },
                      { value: '12h', label: '12 hours' },
                      { value: '24h', label: '24 hours' },
                      { value: '7d', label: '7 days' },
                      { value: '14d', label: '14 days' },
                      { value: '30d', label: '30 days' },
                      { value: '90d', label: '90 days' },
                    ]}
                    className="h-8 text-xs"
                  />
                }
              />
              <CardBody>{trends.data ? <VulnerabilityTrends series={trends.data.series} intraday={intraday} /> : <Skeleton className="h-[240px]" />}</CardBody>
            </Card>
            <Card>
              <CardHeader title="Security posture" description="Weighted by open findings severity" />
              <CardBody className="space-y-5">
                {d ? (
                  <>
                    <div className="flex items-center gap-5">
                      <PostureGauge score={d.security_posture_score} />
                      <div className="text-xs text-muted-foreground">
                        {d.security_posture_score === null ? 'No completed scans yet.' : 'Score = 100·e^(−(10·C + 5·H + 2·M + 0.5·L)/60) over open findings.'}
                      </div>
                    </div>
                    <SeverityBars counts={d.severity_counts} />
                  </>
                ) : (
                  <Skeleton className="h-48" />
                )}
              </CardBody>
            </Card>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Card>
              <CardHeader title="Most vulnerable repositories" action={<Link href="/repositories" className="text-xs text-primary hover:underline">All</Link>} />
              {d?.most_vulnerable_repositories.length ? <MostVulnerableRepos repos={d.most_vulnerable_repositories} /> : <EmptyState title="No scanned repositories" />}
            </Card>
            <Card>
              <CardHeader title="Finding distribution" description="Open findings by type and scanner" />
              <CardBody className="space-y-4 text-sm">
                {d && (
                  <>
                    <Distribution title="Type" data={d.type_counts} />
                    <Distribution title="Primary scanner" data={d.scanner_counts} />
                  </>
                )}
              </CardBody>
            </Card>
            <Card>
              <CardHeader title="Agents & remediation" />
              <CardBody className="space-y-4">
                {d && (
                  <>
                    <div>
                      <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                        <Bot className="h-3.5 w-3.5" /> Investigations
                      </p>
                      {d.investigations.recent.length ? (
                        <ul className="space-y-1.5">
                          {d.investigations.recent.map((i: any) => (
                            <li key={i.id}>
                              <Link href={`/investigations/${i.id}`} className="flex items-center justify-between gap-2 text-xs hover:text-primary">
                                <span className="truncate">{i.finding_title}</span>
                                <span className="flex shrink-0 items-center gap-1.5">
                                  {i.priority && <span className="font-mono text-muted-foreground">{i.priority}</span>}
                                  <StatusBadge status={i.status} />
                                </span>
                              </Link>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-xs text-muted-foreground">No investigations yet. Open a finding and start an AI investigation.</p>
                      )}
                    </div>
                    <div>
                      <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                        <Wrench className="h-3.5 w-3.5" /> Remediation proposals
                      </p>
                      {Object.keys(d.remediation.by_status).length ? (
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(d.remediation.by_status).map(([s, c]) => (
                            <span key={s} className="inline-flex items-center gap-1.5 text-xs">
                              <StatusBadge status={s} /> <span className="tabular">{c as number}</span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground">None yet.</p>
                      )}
                    </div>
                  </>
                )}
              </CardBody>
            </Card>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader title="Recent scans" action={<Link href="/scans" className="text-xs text-primary hover:underline">All scans</Link>} />
              {d?.recent_scans.length ? <RecentScans scans={d.recent_scans} /> : <EmptyState icon={ScanSearch} title="No scans yet" />}
            </Card>
            <Card>
              <CardHeader title="Newest open findings" action={<Link href="/vulnerabilities" className="text-xs text-primary hover:underline">All findings</Link>} />
              {d?.recent_findings.length ? <RecentFindings findings={d.recent_findings} /> : <EmptyState title="No open findings" />}
            </Card>
          </div>
        </>
      )}
    </div>
  )
}

function Distribution({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...entries.map(([, v]) => v))
  return (
    <div>
      <p className="mb-2 text-xs font-medium text-muted-foreground">{title}</p>
      {entries.length === 0 && <p className="text-xs text-muted-foreground">—</p>}
      <div className="space-y-1.5">
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2 text-xs">
            <span className="w-24 truncate">{titleCase(k)}</span>
            <div className="h-1.5 flex-1 rounded-full bg-muted">
              <div className="h-1.5 rounded-full bg-primary/70" style={{ width: `${(v / max) * 100}%` }} />
            </div>
            <span className="tabular w-8 text-right">{v}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
