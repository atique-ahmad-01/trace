'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, Download, ExternalLink } from 'lucide-react'
import { InvestigationResult, Timeline } from '@/components/investigation-view'
import { Badge, Button, Card, CardBody, CardHeader, CodeBlock, DemoBadge, EmptyState, ErrorState, ExtLink, KV, Label, Modal, Notice, PageHeader, Select, SeverityBadge, Skeleton, StatusBadge, Tabs, Textarea } from '@/components/ui'
import { api, download } from '@/lib/api'
import { ago, formatDate, shortSha, titleCase } from '@/lib/utils'

export default function FindingPage({ params }: { params: { id: string } }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState('overview')
  const [statusOpen, setStatusOpen] = useState(false)
  const [mode, setMode] = useState('agentic_rag')
  const f = useQuery({ queryKey: ['finding', params.id], queryFn: () => api.get(`/findings/${params.id}`) })
  const latestId = f.data?.investigations?.[0]?.id
  const inv = useQuery({
    queryKey: ['investigation', latestId],
    queryFn: () => api.get(`/agents/investigations/${latestId}`),
    enabled: !!latestId,
    refetchInterval: (q) => (['queued', 'running'].includes((q.state.data as any)?.status) ? 2500 : false),
  })
  const investigate = useMutation({
    mutationFn: () => api.post(`/findings/${params.id}/investigate`, { mode }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['finding', params.id] })
      setTab('investigation')
    },
  })
  const invStatus = inv.data?.status
  const listedStatus = f.data?.investigations?.[0]?.status
  useEffect(() => {
    if (invStatus && listedStatus && invStatus !== listedStatus) qc.invalidateQueries({ queryKey: ['finding', params.id] })
  }, [invStatus, listedStatus, qc, params.id])
  if (f.error) return <ErrorState error={f.error} />
  if (!f.data) return <Skeleton className="h-96" />
  const d = f.data
  const intel = d.intelligence
  const running = inv.data && ['queued', 'running'].includes(inv.data.status)

  return (
    <div>
      <PageHeader
        back={{ href: '/vulnerabilities', label: 'Vulnerabilities' }}
        title={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} /> {d.title} {d.is_demo && <DemoBadge />}
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <StatusBadge status={d.status} />
            {d.vuln_id && <span className="font-mono">{d.vuln_id}</span>}
            {d.cvss_score && <span>CVSS {d.cvss_score}</span>}
            {intel?.is_known_exploited && <Badge tone="danger">CISA KEV: known exploited</Badge>}
            {d.priority && <Badge tone={d.priority === 'P1' ? 'danger' : d.priority === 'P2' ? 'warning' : 'neutral'}>{d.priority} · risk {d.risk_score}</Badge>}
            <Link href={`/repositories/${d.repository.id}`} className="text-primary hover:underline">{d.repository.full_name}</Link>
          </span>
        }
        actions={
          <>
            <Button variant="outline" onClick={() => download(`/reports/finding/${d.id}?format=pdf`, `trace-finding-${d.id.slice(0, 8)}.pdf`)}>
              <Download /> Report
            </Button>
            <Button variant="outline" onClick={() => setStatusOpen(true)}>Change status</Button>
            <Select value={mode} onChange={setMode} aria-label="Investigation mode" className="h-9 text-xs" options={[{ value: 'agentic_rag', label: 'Agentic RAG (tools + retrieval)' }, { value: 'rag', label: 'RAG only' }, { value: 'base', label: 'Base model' }]} />
            <Button onClick={() => investigate.mutate()} loading={investigate.isPending} disabled={!!running}>
              <Bot /> {running ? 'Investigating…' : 'Investigate with AI'}
            </Button>
          </>
        }
      />
      {investigate.error ? <ErrorState error={investigate.error} className="mb-4" /> : null}
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'investigation', label: <span className="inline-flex items-center gap-1.5">AI investigation {running && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />}</span> },
          { value: 'remediation', label: `Remediation (${d.proposals.length})` },
        ]}
      />

      {tab === 'overview' && (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            <Card>
              <CardHeader title="Finding" description={`Detected by ${(d.detected_by?.length ? d.detected_by : [d.scanner_name]).join(', ')}`} />
              <CardBody className="space-y-4">
                <KV
                  items={[
                    ['Type', titleCase(d.finding_type)],
                    ['Rule', <span key="r" className="font-mono text-xs">{d.rule_id}</span>],
                    ['Identifiers', [d.vuln_id, ...(d.aliases || [])].filter(Boolean).join(', ') || '—'],
                    ['CWE', (d.cwe_ids || []).join(', ') || '—'],
                    ['File', d.file_path ? <span key="f" className="font-mono text-xs">{d.file_path}{d.start_line ? `:${d.start_line}` : ''}</span> : '—'],
                    ...(d.package_name
                      ? ([
                          ['Package', <span key="p" className="font-mono text-xs">{d.package_name} ({d.package_ecosystem})</span>],
                          ['Installed', <span key="i" className="font-mono text-xs">{d.installed_version}</span>],
                          ['Fixed in', <span key="x" className="font-mono text-xs text-success">{d.fixed_version || 'no fix published'}</span>],
                        ] as [React.ReactNode, React.ReactNode][])
                      : []),
                    ['Commit', <span key="c" className="font-mono text-xs">{shortSha(d.commit_sha)}</span>],
                    ['First / last seen', `${formatDate(d.first_seen_at)} · ${ago(d.last_seen_at)}`],
                  ]}
                />
                {d.description && <p className="whitespace-pre-line text-sm text-muted-foreground">{d.description.slice(0, 2500)}</p>}
                {d.code_snippet && <CodeBlock code={d.code_snippet} />}
                {d.finding_type === 'secret' && <Notice tone="warning">Secret values are redacted by the scanner and never stored by TRACE. Rotate the credential at its provider.</Notice>}
              </CardBody>
            </Card>
            {d.references?.length > 0 && (
              <Card>
                <CardHeader title="Scanner references" />
                <CardBody>
                  <ul className="space-y-1 text-xs">
                    {d.references.slice(0, 12).map((r: string) => (
                      <li key={r} className="truncate">
                        <ExtLink href={r}>{r}</ExtLink>
                      </li>
                    ))}
                  </ul>
                </CardBody>
              </Card>
            )}
          </div>
          <Card className="h-fit">
            <CardHeader title="Vulnerability intelligence" description={intel ? `Fetched ${ago(intel.fetched_at)}` : undefined} />
            <CardBody className="space-y-3">
              {!d.vuln_id ? (
                <p className="text-xs text-muted-foreground">Not applicable — this finding has no CVE/advisory identifier (code, secret or configuration issue).</p>
              ) : !intel ? (
                <p className="text-xs text-muted-foreground">Not enriched yet. Enrichment runs after each scan; NVD rate limits may delay it.</p>
              ) : (
                <>
                  <KV
                    items={[
                      ['CVSS', intel.cvss_score ? `${intel.cvss_score} ${intel.cvss_severity || ''}` : 'unavailable'],
                      ['Vector', <span key="v" className="break-all font-mono text-[11px]">{intel.cvss_vector || '—'}</span>],
                      ['Published', formatDate(intel.published_at)],
                      ['Modified', formatDate(intel.modified_at)],
                      ['Known exploited', intel.is_known_exploited === null ? 'Unknown — KEV unavailable' : intel.is_known_exploited ? <Badge key="k" tone="danger">Yes (CISA KEV)</Badge> : 'Not in CISA KEV'],
                      ['Exploit refs', intel.exploit_references?.length || 0],
                      ['Fixed versions', (intel.fixed_versions || []).join(', ') || 'none published'],
                    ]}
                  />
                  {intel.kev && <Notice tone="danger">CISA due {intel.kev.due_date}: {intel.kev.required_action}</Notice>}
                  {intel.remediation && <p className="text-xs">{intel.remediation}</p>}
                  <div>
                    <p className="mb-1 text-xs font-medium text-muted-foreground">Source status</p>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(intel.sources || {}).map(([k, v]: any) => (
                        <a key={k} href={v.url || undefined} target="_blank" rel="noreferrer">
                          <Badge tone={v.status === 'ok' ? 'success' : v.status === 'not_found' || v.status === 'skipped' ? 'neutral' : 'warning'} title={v.status}>
                            {k}: {v.status.split(':')[0]}
                          </Badge>
                        </a>
                      ))}
                    </div>
                  </div>
                  {intel.references?.length > 0 && (
                    <details className="text-xs">
                      <summary className="cursor-pointer text-muted-foreground">{intel.references.length} references</summary>
                      <ul className="mt-1 space-y-1">
                        {intel.references.slice(0, 25).map((r: any) => (
                          <li key={r.url} className="truncate">
                            <ExtLink href={r.url}>{r.url}</ExtLink> <span className="text-muted-foreground">[{r.source}]</span>
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                  <Link href={`/intelligence?id=${encodeURIComponent(d.vuln_id)}`} className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                    Open in intelligence <ExternalLink className="h-3 w-3" />
                  </Link>
                </>
              )}
            </CardBody>
          </Card>
        </div>
      )}

      {tab === 'investigation' &&
        (!latestId ? (
          <Card>
            <EmptyState icon={Bot} title="No AI investigation yet" description="The supervisor coordinates research, code analysis, risk assessment and remediation agents. Every claim is linked to evidence." action={<Button onClick={() => investigate.mutate()} loading={investigate.isPending}>Start investigation</Button>} />
          </Card>
        ) : inv.data ? (
          <div className="grid gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2">
              {running ? (
                <Card>
                  <EmptyState icon={Bot} title="Agents are working…" description="Results appear when the supervisor finalizes. Follow progress in the timeline." />
                </Card>
              ) : (
                <InvestigationResult inv={inv.data} />
              )}
            </div>
            <Card className="h-fit">
              <CardHeader title="Agent timeline" description={<Link className="text-primary hover:underline" href={`/investigations/${inv.data.id}`}>Open investigation</Link>} />
              <CardBody>
                <Timeline events={inv.data.events} />
              </CardBody>
            </Card>
          </div>
        ) : (
          <Skeleton className="h-64" />
        ))}

      {tab === 'remediation' && (
        <div className="space-y-4">
          {d.proposals.length === 0 && (
            <Card>
              <EmptyState title="No remediation proposals" description="Run an AI investigation; the remediation agent creates a proposal (patch or guidance) that requires human approval." />
            </Card>
          )}
          {d.proposals.map((p: any) => (
            <Card key={p.id}>
              <CardHeader title={<Link href={`/remediation/${p.id}`} className="hover:text-primary">{p.title}</Link>} description={`${titleCase(p.remediation_type)} · proposed ${ago(p.created_at)}`} action={<StatusBadge status={p.status} />} />
              <CardBody className="text-sm">
                {p.root_cause && <p className="mb-2">{p.root_cause}</p>}
                <Link href={`/remediation/${p.id}`} className="text-xs text-primary hover:underline">Review proposal →</Link>
              </CardBody>
            </Card>
          ))}
          {d.verifications.length > 0 && (
            <Card>
              <CardHeader title="Verification history" />
              <CardBody className="space-y-2 text-sm">
                {d.verifications.map((v: any) => (
                  <div key={v.id} className="flex items-center justify-between">
                    <span>
                      {formatDate(v.created_at)} — target present before: {String(v.target_finding_present_before)}, after: {String(v.target_finding_present_after)}
                    </span>
                    <StatusBadge status={v.status} />
                  </div>
                ))}
              </CardBody>
            </Card>
          )}
        </div>
      )}
      <StatusModal open={statusOpen} onClose={() => setStatusOpen(false)} finding={d} />
    </div>
  )
}

function StatusModal({ open, onClose, finding }: { open: boolean; onClose: () => void; finding: any }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState(finding.status)
  const [reason, setReason] = useState('')
  const m = useMutation({
    mutationFn: () => api.patch(`/findings/${finding.id}`, { status, reason: reason || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['finding', finding.id] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      onClose()
    },
  })
  return (
    <Modal open={open} onClose={onClose} title="Change finding status" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={() => m.mutate()} loading={m.isPending}>Save</Button></>}>
      <div className="space-y-3">
        <div>
          <Label>Status</Label>
          <Select value={status} onChange={setStatus} className="w-full" options={['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'].map((s) => ({ value: s, label: titleCase(s.toLowerCase()) }))} />
        </div>
        <div>
          <Label hint="required for false positive / accepted risk; recorded in the audit log">Reason</Label>
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        {m.error ? <ErrorState error={m.error} /> : null}
      </div>
    </Modal>
  )
}
