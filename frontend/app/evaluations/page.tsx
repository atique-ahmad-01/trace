'use client'

import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BarChart3, Play } from 'lucide-react'
import { ChartTooltip } from '@/components/dashboard/vulnerability-trends'
import { Badge, Button, Card, CardBody, CardHeader, Checkbox, EmptyState, ErrorState, Input, Label, Notice, PageHeader, Pagination, Select, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago, pct, titleCase } from '@/lib/utils'

const MODE_COLOR: Record<string, string> = { base: 'hsl(220 10% 60%)', rag: 'hsl(205 80% 60%)', agentic_rag: 'hsl(186 72% 46%)' }
const RATE_METRICS = ['vulnerability_identification_accuracy', 'cwe_accuracy', 'severity_accuracy', 'remediation_correctness', 'false_positive_rate', 'false_negative_rate', 'prompt_injection_resistance', 'cve_recall', 'cve_precision', 'hallucinated_id_rate', 'evidence_groundedness', 'citation_coverage', 'tool_use_correctness', 'task_completion']

export default function EvaluationsPage() {
  const router = useRouter()
  const qc = useQueryClient()
  const datasets = useQuery<any[]>({ queryKey: ['eval-datasets'], queryFn: () => api.get('/evaluations/datasets') })
  const [ds, setDs] = useState('')
  const [modes, setModes] = useState(['base', 'rag', 'agentic_rag'])
  const [model, setModel] = useState('')
  const [limit, setLimit] = useState('')
  const [page, setPage] = useState(1)
  useEffect(() => {
    if (!ds && datasets.data?.length) setDs(datasets.data[0].id)
  }, [datasets.data, ds])
  const runs = useQuery<Paged<any>>({
    queryKey: ['eval-runs', page],
    queryFn: () => api.get(`/evaluations/runs${qs({ page })}`),
    refetchInterval: (q) => ((q.state.data as any)?.items?.some((r: any) => ['queued', 'running'].includes(r.status)) ? 4000 : false),
  })
  const compare = useQuery({ queryKey: ['eval-compare', ds, runs.data?.items.map((r) => r.status).join()], queryFn: () => api.get(`/evaluations/compare?dataset_id=${ds}`), enabled: !!ds })
  const run = useMutation({ mutationFn: () => api.post('/evaluations/runs', { dataset_id: ds, modes, model: model || undefined, case_limit: limit ? Number(limit) : undefined }), onSuccess: () => qc.invalidateQueries({ queryKey: ['eval-runs'] }) })
  const configs = compare.data?.configurations || []
  const metricKeys = RATE_METRICS.filter((m) => configs.some((c: any) => c.metrics?.[m] !== undefined && c.metrics?.[m] !== null))
  const chartData = metricKeys.map((m) => ({ metric: titleCase(m).replace('Vulnerability Identification', 'Vuln ID'), ...Object.fromEntries(configs.map((c: any) => [`${c.mode} · ${c.model}`, c.metrics?.[m] !== null && c.metrics?.[m] !== undefined ? Math.round(c.metrics[m] * 1000) / 10 : null])) }))
  const selected = datasets.data?.find((d) => d.id === ds)

  return (
    <div>
      <PageHeader title="AI evaluations" description="Measure TRACE's own agents: accuracy, false positives/negatives, groundedness, citation coverage, injection resistance, tool use, latency, tokens and cost." />
      <Notice className="mb-4">Metrics appear only for runs that have actually executed. Configurations that were not run are labeled as such — no benchmark numbers are pre-filled.</Notice>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Run an evaluation" />
          <CardBody className="space-y-3">
            <div>
              <Label>Dataset</Label>
              <Select value={ds} onChange={setDs} className="w-full" options={(datasets.data || []).map((d) => ({ value: d.id, label: `${d.name} (${d.case_count})` }))} />
              {selected && <p className="mt-1 text-[11px] text-muted-foreground">{selected.description}</p>}
            </div>
            <div>
              <Label>Modes to compare</Label>
              <div className="flex flex-col gap-1.5">
                {[['base', 'Base model (no RAG)'], ['rag', 'Model + RAG'], ['agentic_rag', 'Agentic RAG (tools + retrieval)']].map(([m, l]) => (
                  <Checkbox key={m} checked={modes.includes(m)} onChange={(v) => setModes(v ? [...modes, m] : modes.filter((x) => x !== m))} label={l} />
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div><Label hint="blank = default">Model</Label><Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="qwen2.5-coder:7b" /></div>
              <div><Label hint="optional">Case limit</Label><Input type="number" min={1} value={limit} onChange={(e) => setLimit(e.target.value)} /></div>
            </div>
            <Button className="w-full" onClick={() => run.mutate()} loading={run.isPending} disabled={!ds || !modes.length}><Play /> Start {modes.length} run{modes.length === 1 ? '' : 's'}</Button>
            {run.error ? <ErrorState error={run.error} /> : null}
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Comparison" description={selected ? `Latest completed run per mode/model on “${selected.name}”` : undefined} />
          <CardBody>
            {compare.data?.not_run?.length > 0 && <p className="mb-3 text-xs text-muted-foreground">Not run yet: {compare.data.not_run.map((m: string) => <Badge key={m} className="mr-1">{titleCase(m)}</Badge>)}</p>}
            {configs.length ? (
              <>
                <ResponsiveContainer width="100%" height={Math.max(240, metricKeys.length * 34)}>
                  <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 16 }}>
                    <CartesianGrid stroke="hsl(var(--border))" horizontal={false} />
                    <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="metric" width={150} tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: 'hsl(var(--muted) / 0.4)' }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    {configs.map((c: any) => (
                      <Bar key={`${c.mode} · ${c.model}`} dataKey={`${c.mode} · ${c.model}`} fill={MODE_COLOR[c.mode] || 'hsl(var(--primary))'} radius={[0, 3, 3, 0]} barSize={8} isAnimationActive={false} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
                <Table className="mt-4">
                  <THead><tr><Th>Configuration</Th><Th>Cases</Th><Th>Latency p50</Th><Th>Tokens</Th><Th>Est. cost</Th></tr></THead>
                  <tbody>
                    {configs.map((c: any) => (
                      <Tr key={c.run_id} onClick={() => router.push(`/evaluations/runs/${c.run_id}`)}>
                        <Td className="text-xs"><span className="mr-2 inline-block h-2 w-2 rounded-sm" style={{ background: MODE_COLOR[c.mode] }} />{titleCase(c.mode)} · <span className="font-mono">{c.model}</span></Td>
                        <Td className="tabular text-xs">{c.metrics.cases}</Td>
                        <Td className="tabular text-xs">{c.metrics.latency_ms_p50 ? `${(c.metrics.latency_ms_p50 / 1000).toFixed(1)}s` : '—'}</Td>
                        <Td className="tabular text-xs">{c.metrics.tokens_in + c.metrics.tokens_out}</Td>
                        <Td className="tabular text-xs">{c.metrics.estimated_cost_usd === null ? 'n/a (local model)' : `$${c.metrics.estimated_cost_usd}`}</Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </>
            ) : <EmptyState icon={BarChart3} title="No completed runs for this dataset" description="Start a run to compare base, RAG and agentic RAG configurations." />}
          </CardBody>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader title="Evaluation history" />
        {runs.isLoading ? <Skeleton className="m-4 h-32" /> : runs.data?.items.length ? (
          <>
            <Table>
              <THead><tr><Th>Run</Th><Th>Dataset</Th><Th>Mode</Th><Th>Model</Th><Th>Status</Th><Th>Key metric</Th><Th>Started</Th></tr></THead>
              <tbody>
                {runs.data.items.map((r) => (
                  <Tr key={r.id} onClick={() => router.push(`/evaluations/runs/${r.id}`)}>
                    <Td className="max-w-[260px] truncate text-xs">{r.name}</Td>
                    <Td className="text-xs">{r.dataset_name}</Td>
                    <Td className="text-xs">{titleCase(r.mode)}</Td>
                    <Td className="font-mono text-xs">{r.model}</Td>
                    <Td><StatusBadge status={r.status} /></Td>
                    <Td className="tabular text-xs">{r.status === 'completed' && r.metrics ? (r.task_type === 'cve_matching' ? `CVE recall ${pct(r.metrics.cve_recall)}` : `Accuracy ${pct(r.metrics.vulnerability_identification_accuracy)}`) : 'not available'}</Td>
                    <Td className="text-xs text-muted-foreground">{ago(r.created_at)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
            <Pagination page={runs.data.page} pages={runs.data.pages} total={runs.data.total} onPage={setPage} />
          </>
        ) : <EmptyState title="No evaluation runs yet" />}
      </Card>
    </div>
  )
}
