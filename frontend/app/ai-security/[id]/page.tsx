'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { Badge, Button, Card, CardBody, CardHeader, CodeBlock, ErrorState, Notice, PageHeader, Select, SeverityBadge, Skeleton, Stat, StatusBadge } from '@/components/ui'
import { api, download } from '@/lib/api'
import { formatDate, titleCase } from '@/lib/utils'

export default function AssessmentPage({ params }: { params: { id: string } }) {
  const [filter, setFilter] = useState('failed')
  const q = useQuery({
    queryKey: ['assessment', params.id],
    queryFn: () => api.get(`/ai-security/assessments/${params.id}`),
    refetchInterval: (x) => (['queued', 'running'].includes((x.state.data as any)?.status) ? 2500 : false),
  })
  if (q.error) return <ErrorState error={q.error} />
  if (!q.data) return <Skeleton className="h-96" />
  const a = q.data
  const results = a.results.filter((r: any) => !filter || r.outcome === filter)
  return (
    <div>
      <PageHeader
        back={{ href: '/ai-security', label: 'AI security' }}
        title={<span className="flex items-center gap-2">{a.name} <StatusBadge status={a.status} /></span>}
        description={`${titleCase(a.target_type)}${a.repository_name ? ` · ${a.repository_name}` : a.target_config?.model ? ` · ${a.target_config.provider}:${a.target_config.model}` : ''} · ${formatDate(a.created_at)}`}
        actions={a.status === 'completed' && <Button variant="outline" onClick={() => download(`/reports/ai-security/${a.id}?format=pdf`, `trace-ai-security-${a.id.slice(0, 8)}.pdf`)}><Download /> PDF report</Button>}
      />
      {a.error_message && <ErrorState error={a.error_message} className="mb-4" />}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat label="Tests" value={a.total_tests} />
        <Stat label="Risk found" value={a.tests_failed} tone="hsl(var(--sev-high))" />
        <Stat label="Passed" value={a.tests_passed} />
        <Stat label="Errored" value={a.tests_errored} />
        <Stat label="Risk score" value={a.risk_score ?? '—'} sub="0–10, severity-weighted" />
      </div>
      {a.summary && <Notice className="mt-4">{a.summary}</Notice>}
      <div className="mb-3 mt-6 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Results</h2>
        <Select value={filter} onChange={setFilter} className="h-8 text-xs" aria-label="Filter outcome" options={[{ value: 'failed', label: 'Risk found' }, { value: '', label: 'All outcomes' }, { value: 'passed', label: 'Passed' }, { value: 'error', label: 'Errored' }, { value: 'not_applicable', label: 'Not applicable' }]} />
      </div>
      <div className="space-y-3">
        {results.map((r: any) => (
          <Card key={r.id}>
            <CardHeader
              title={<span className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-muted-foreground">{r.test_id}</span> {r.title} {r.severity && <SeverityBadge severity={r.severity} />}</span>}
              description={`${titleCase(r.category)}${r.file_path ? ` · ${r.file_path}:${r.line_number}` : ''}`}
              action={<span className="flex items-center gap-2"><Badge tone={r.verification_status === 'demonstrated' ? 'danger' : r.verification_status === 'needs_review' ? 'warning' : 'neutral'}>{titleCase(r.verification_status)}</Badge><StatusBadge status={r.outcome === 'failed' ? 'risk found' : r.outcome} /></span>}
            />
            <CardBody className="space-y-3 text-sm">
              {r.description && <p className="text-muted-foreground">{r.description}</p>}
              {r.impact && <p><span className="text-muted-foreground">Impact: </span>{r.impact}</p>}
              {r.evidence?.judgement && <p><span className="text-muted-foreground">Judgement: </span>{r.evidence.judgement}</p>}
              {r.evidence?.output_excerpt && <CodeBlock code={r.evidence.output_excerpt} />}
              {r.evidence?.matches?.length > 0 && <CodeBlock code={r.evidence.matches.map((m: any) => `${m.file}:${m.line}  ${m.code}`).join('\n')} />}
              {r.reproduction && <details className="text-xs"><summary className="cursor-pointer text-muted-foreground">Reproduction</summary><CodeBlock code={r.reproduction} className="mt-1" /></details>}
              <p className="text-xs"><span className="text-muted-foreground">Mitigation: </span>{r.mitigation}</p>
            </CardBody>
          </Card>
        ))}
        {!results.length && <p className="text-sm text-muted-foreground">{a.status === 'completed' ? 'No results with this outcome.' : 'Assessment running…'}</p>}
      </div>
    </div>
  )
}
