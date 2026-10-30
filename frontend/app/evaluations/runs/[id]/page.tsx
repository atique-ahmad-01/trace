'use client'

import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { Button, Card, CardBody, CardHeader, ErrorState, Notice, PageHeader, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, download } from '@/lib/api'
import { formatDate, titleCase } from '@/lib/utils'

function fmtMetric(k: string, v: any) {
  if (v === null || v === undefined) return '—'
  if (typeof v !== 'number') return String(v)
  if (k.includes('latency')) return `${(v / 1000).toFixed(1)}s`
  if (k.startsWith('tokens') || k === 'cases') return String(v)
  if (k.includes('cost')) return `$${v}`
  return `${(v * 100).toFixed(1)}%`
}

export default function EvalRunPage({ params }: { params: { id: string } }) {
  const q = useQuery({
    queryKey: ['eval-run', params.id],
    queryFn: () => api.get(`/evaluations/runs/${params.id}`),
    refetchInterval: (x) => (['queued', 'running'].includes((x.state.data as any)?.status) ? 3000 : false),
  })
  if (q.error) return <ErrorState error={q.error} />
  if (!q.data) return <Skeleton className="h-96" />
  const r = q.data
  return (
    <div>
      <PageHeader
        back={{ href: '/evaluations', label: 'Evaluations' }}
        title={<span className="flex items-center gap-2">{r.name} <StatusBadge status={r.status} /></span>}
        description={`${r.dataset_name} · ${titleCase(r.mode)} · ${r.provider}:${r.model} · ${formatDate(r.started_at)}`}
        actions={r.status === 'completed' && <Button variant="outline" onClick={() => download(`/reports/evaluation/${r.id}?format=pdf`, `trace-eval-${r.id.slice(0, 8)}.pdf`)}><Download /> PDF report</Button>}
      />
      {r.error_message && <Notice tone="warning" className="mb-4">{r.error_message}</Notice>}
      <Card className="mb-4">
        <CardHeader title="Metrics" description={r.status === 'completed' ? 'Computed from the case results below' : `Run ${r.status} — ${r.results.length} case(s) recorded so far; aggregate metrics are not reported until completion.`} />
        {r.metrics ? (
          <CardBody className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-3 xl:grid-cols-4">
            {Object.entries(r.metrics).map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3 border-b py-1.5">
                <span className="text-muted-foreground">{titleCase(k)}</span>
                <span className="tabular font-medium">{fmtMetric(k, v)}</span>
              </div>
            ))}
          </CardBody>
        ) : null}
      </Card>
      <Card>
        <CardHeader title="Case results" />
        <Table>
          <THead><tr><Th>Case</Th><Th>Expected</Th><Th>Output</Th><Th>Scores</Th><Th>Pass</Th><Th>Latency</Th></tr></THead>
          <tbody>
            {r.results.map((c: any) => (
              <Tr key={c.id}>
                <Td className="font-mono text-xs">{c.case_key}</Td>
                <Td className="max-w-[200px] font-mono text-[11px] text-muted-foreground">{c.expected.vulnerable !== undefined ? `vuln=${c.expected.vulnerable} ${(c.expected.cwe || []).join('/')}` : (c.expected.cve_any || []).join(', ')}</Td>
                <Td className="max-w-[320px] text-[11px]">
                  {c.error_message ? <span className="text-destructive">{c.error_message}</span> : c.output?.parsed ? (
                    <span className="line-clamp-3">{c.output.parsed.cve_ids ? (c.output.parsed.cve_ids || []).join(', ') || '(none)' : `vuln=${c.output.parsed.vulnerable} ${c.output.parsed.cwe || ''} ${c.output.parsed.severity || ''} — ${c.output.parsed.explanation || ''}`}</span>
                  ) : <span className="text-warning">unparseable output</span>}
                  {c.output?.tools_called?.length > 0 && <span className="block font-mono text-muted-foreground">tools: {c.output.tools_called.join(', ')}</span>}
                </Td>
                <Td className="max-w-[220px] font-mono text-[10px] text-muted-foreground">{Object.entries(c.scores || {}).filter(([k]) => k !== 'predicted').map(([k, v]) => `${k}=${v}`).join(' ')}</Td>
                <Td>{c.passed === null ? '—' : c.passed ? <StatusBadge status="passed" /> : <StatusBadge status="failed" />}</Td>
                <Td className="tabular text-xs">{c.latency_ms ? `${(c.latency_ms / 1000).toFixed(1)}s` : '—'}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </div>
  )
}
