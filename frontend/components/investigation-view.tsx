'use client'

import { useState } from 'react'
import { AlertTriangle, BookOpen, Bot, CheckCircle2, CircleDashed, Cpu, FileSearch, Gauge, Wrench, XCircle } from 'lucide-react'
import { Badge, Card, CardBody, CardHeader, DiffView, ExtLink, KV, Notice, StatusBadge } from '@/components/ui'
import { cn, titleCase } from '@/lib/utils'

const AGENT_ICON: Record<string, React.ElementType> = {
  supervisor: Bot,
  vulnerability_research: BookOpen,
  code_analysis: FileSearch,
  risk_assessment: Gauge,
  remediation: Wrench,
  verification: CheckCircle2,
}

function Claims({ claims, evidence }: { claims?: any[]; evidence: any[] }) {
  if (!claims?.length) return null
  return (
    <ul className="space-y-1.5">
      {claims.map((c, i) => (
        <li key={i} className="flex gap-2 text-sm">
          {c.supported ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> : <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />}
          <span>
            {c.text}{' '}
            {c.citations.map((id: string) => {
              const e = evidence.find((x) => x.citation_id === id)
              return (
                <a key={id} href={`#ev-${id}`} title={e?.title} className="ml-0.5 rounded bg-primary/10 px-1 font-mono text-[10px] text-primary hover:bg-primary/20">
                  {id}
                </a>
              )
            })}
            {!c.supported && <span className="ml-1 text-[11px] text-warning">(unsupported by retrieved evidence — model reasoning)</span>}
          </span>
        </li>
      ))}
    </ul>
  )
}

export function Timeline({ events }: { events: any[] }) {
  const [open, setOpen] = useState<number | null>(null)
  if (!events.length) return <p className="text-xs text-muted-foreground">No events yet.</p>
  return (
    <ol className="relative space-y-0">
      {events.map((e, i) => {
        const Icon = AGENT_ICON[e.agent_name] || Cpu
        const isErr = e.event_type === 'error'
        return (
          <li key={e.id} className="relative flex gap-3 pb-3">
            {i < events.length - 1 && <span className="absolute left-[11px] top-6 h-full w-px bg-border" aria-hidden />}
            <span className={cn('z-10 mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border bg-surface', isErr && 'border-destructive/50 text-destructive', e.event_type === 'complete' && 'border-success/50 text-success')}>
              {isErr ? <XCircle className="h-3.5 w-3.5" /> : <Icon className="h-3.5 w-3.5" />}
            </span>
            <div className="min-w-0 flex-1">
              <button className="w-full text-left" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
                <p className="text-xs">
                  <span className="font-medium">{titleCase(e.agent_name)}</span> <span className="text-muted-foreground">· {e.event_type.replace('_', ' ')}</span>
                  {e.duration_ms ? <span className="text-muted-foreground"> · {(e.duration_ms / 1000).toFixed(1)}s</span> : null}
                </p>
                <p className={cn('text-sm', isErr && 'text-destructive')}>{e.message}</p>
              </button>
              {open === i && e.data && Object.keys(e.data).length > 0 && (
                <pre className="scrollbar-thin mt-1.5 max-h-64 overflow-auto rounded border bg-background p-2 font-mono text-[11px]">{JSON.stringify(e.data, null, 2)}</pre>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

export function InvestigationResult({ inv }: { inv: any }) {
  const evidence: any[] = inv.evidence || []
  const research = inv.research || {}
  const code = inv.code_analysis || {}
  const risk = inv.risk_assessment || {}
  const rem = inv.remediation || {}
  const facts = research.facts || {}
  const kev = facts.known_exploited
  return (
    <div className="space-y-4">
      {inv.error_message && <Notice tone="warning">{inv.error_message}</Notice>}
      {inv.summary && (
        <Card>
          <CardHeader title="Investigation summary" description={`${inv.model || ''} · ${inv.mode} · ${inv.tokens_in + inv.tokens_out} tokens${inv.latency_ms ? ` · ${(inv.latency_ms / 1000).toFixed(0)}s` : ''}`} />
          <CardBody className="text-sm leading-relaxed">{inv.summary}</CardBody>
        </Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Vulnerability research" description="Facts below come from structured sources, not the model" />
          <CardBody className="space-y-3">
            <KV
              items={[
                ['Identifier', facts.vuln_id],
                ['CVSS', facts.cvss_score ? `${facts.cvss_score}${facts.cvss_vector ? ` · ${facts.cvss_vector}` : ''}` : 'unavailable'],
                ['Fixed versions', (facts.fixed_versions || []).join(', ') || 'none published'],
                ['CISA KEV', kev === true ? <Badge key="k" tone="danger">Known exploited</Badge> : kev === false ? 'Not listed' : 'Unavailable (not a negative result)'],
                ['Version confirmed', research.version_confirmed_affected === true ? 'Yes — OSV lists this exact version' : research.version_confirmed_affected === false ? 'Not confirmed by OSV query' : '—'],
                ['Sources', Object.entries(facts.sources || {}).map(([k, v]) => `${k}: ${v}`).join(' · ') || '—'],
              ]}
            />
            {research.model_summary && (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Model analysis (grounded claims marked)</p>
                <p className="mb-2 text-sm">{research.model_summary}</p>
                <Claims claims={research.claims} evidence={evidence} />
              </div>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Risk assessment" description="Deterministic score; model explains impact" />
          <CardBody className="space-y-3">
            {risk.risk_score !== undefined ? (
              <>
                <div className="flex items-baseline gap-3">
                  <span className="tabular text-3xl font-semibold">{risk.risk_score}</span>
                  <span className="text-sm text-muted-foreground">/ 10</span>
                  <Badge tone={risk.priority === 'P1' ? 'danger' : risk.priority === 'P2' ? 'warning' : 'neutral'}>{risk.priority}</Badge>
                </div>
                <ul className="space-y-1 text-xs">
                  {(risk.factors || []).map((f: any, i: number) => (
                    <li key={i} className="flex justify-between gap-3">
                      <span className="text-muted-foreground">{f.detail}</span>
                      <span className="tabular font-mono">{typeof f.value === 'number' && f.factor !== 'base' ? (f.value > 0 ? `+${f.value}` : f.value) : f.value}</span>
                    </li>
                  ))}
                </ul>
                {risk.rationale && <p className="text-sm">{risk.rationale}</p>}
                {risk.business_impact && (
                  <p className="text-sm">
                    <span className="text-muted-foreground">Impact: </span>
                    {risk.business_impact}
                  </p>
                )}
                <Claims claims={risk.claims} evidence={evidence} />
              </>
            ) : (
              <p className="text-xs text-muted-foreground">Not available.</p>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Code security analysis" description="Confirmed facts vs. hypotheses" />
          <CardBody className="space-y-3 text-sm">
            {code.attack_path && (
              <p>
                <span className="text-muted-foreground">Attack path: </span>
                {code.attack_path}
              </p>
            )}
            {code.data_flow && (
              <p>
                <span className="text-muted-foreground">Data flow: </span>
                {code.data_flow}
              </p>
            )}
            <KV items={[['Reachable', code.reachable || 'unknown'], ['Static usage', code.static_reachability === null || code.static_reachability === undefined ? '—' : code.static_reachability ? `${code.direct_usages?.length} direct import(s)` : 'no direct imports found'], ['Exposure', code.exposure]]} />
            {code.confirmed?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-medium text-success">Confirmed</p>
                <ul className="list-disc space-y-0.5 pl-5">{code.confirmed.map((c: string, i: number) => <li key={i}>{c}</li>)}</ul>
              </div>
            )}
            {code.hypotheses?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-medium text-warning">Hypotheses (unverified)</p>
                <ul className="list-disc space-y-0.5 pl-5">{code.hypotheses.map((c: string, i: number) => <li key={i}>{c}</li>)}</ul>
              </div>
            )}
            {code.direct_usages?.length > 0 && (
              <pre className="scrollbar-thin max-h-32 overflow-auto rounded border bg-background p-2 font-mono text-[11px]">{code.direct_usages.map((u: any) => `${u.path}:${u.line}  ${u.text}`).join('\n')}</pre>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Remediation" description={rem.type ? titleCase(rem.type) : undefined} />
          <CardBody className="space-y-3 text-sm">
            {rem.root_cause && (
              <p>
                <span className="text-muted-foreground">Root cause: </span>
                {rem.root_cause}
              </p>
            )}
            {rem.steps?.length > 0 && <ol className="list-decimal space-y-0.5 pl-5">{rem.steps.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol>}
            {rem.side_effects && (
              <p className="text-xs">
                <span className="text-muted-foreground">Side effects: </span>
                {rem.side_effects}
              </p>
            )}
            {rem.patch && <DiffView diff={rem.patch} />}
            <p className="text-xs text-muted-foreground">Evidence sufficient for automated application: {rem.evidence_sufficient ? 'yes' : 'no'}. Changes are applied only after human approval.</p>
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Evidence & citations" description="Retrieved documents and structured records. Retrieved text is treated as untrusted data." />
        <CardBody className="space-y-2">
          {evidence.length ? (
            evidence.map((e) => (
              <div key={e.citation_id} id={`ev-${e.citation_id}`} className="rounded-md border p-3">
                <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                  <span className="rounded bg-primary/10 px-1 font-mono text-primary">{e.citation_id}</span>
                  <span className="font-medium">
                    <ExtLink href={e.url}>{e.title}</ExtLink>
                  </span>
                  <Badge>{e.kind === 'structured' ? 'structured record' : e.source_type}</Badge>
                  {e.retrieval?.length > 0 && <span className="text-muted-foreground">via {e.retrieval.join(' + ')}</span>}
                </div>
                <p className="line-clamp-4 whitespace-pre-line text-xs text-muted-foreground">{e.text}</p>
              </div>
            ))
          ) : (
            <p className="text-xs text-muted-foreground">No evidence retrieved.</p>
          )}
        </CardBody>
      </Card>
    </div>
  )
}

export function InvestigationStatusLine({ inv }: { inv: any }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
      {['queued', 'running'].includes(inv.status) ? <CircleDashed className="h-3.5 w-3.5 animate-spin" /> : null}
      <StatusBadge status={inv.status} /> {inv.model}
    </span>
  )
}
