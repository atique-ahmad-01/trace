'use client'

import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BarChart3, Bot, Brain, Check, Code2, Database, Library, Play, ShieldAlert } from 'lucide-react'
import { ChartTooltip } from '@/components/dashboard/vulnerability-trends'
import { Button, Card, CardBody, CardHeader, EmptyState, ErrorState, Input, Label, Notice, PageHeader, Pagination, Skeleton, StatusBadge, THead, Table, Td, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { ago, cn, pct, titleCase } from '@/lib/utils'

const MODES: Record<string, { label: string; detail: string; color: string; icon: React.ElementType }> = {
  base: { label: 'Base model', detail: 'The model alone, no retrieval', color: 'hsl(220 10% 60%)', icon: Brain },
  rag: { label: 'Model + RAG', detail: 'Adds retrieved OWASP, CWE and intel context', color: 'hsl(205 80% 60%)', icon: Library },
  agentic_rag: { label: 'Agentic RAG', detail: 'Agents with tools and retrieval', color: 'hsl(186 72% 46%)', icon: Bot },
}
const modeLabel = (m: string) => MODES[m]?.label || titleCase(m)
const RATE_METRICS = ['vulnerability_identification_accuracy', 'cwe_accuracy', 'severity_accuracy', 'remediation_correctness', 'false_positive_rate', 'false_negative_rate', 'prompt_injection_resistance', 'cve_recall', 'cve_precision', 'hallucinated_id_rate', 'evidence_groundedness', 'citation_coverage', 'tool_use_correctness', 'task_completion']
// First metric present on a run is its headline score.
const HEADLINE = [
  ['prompt_injection_resistance', 'Injection resistance'],
  ['cve_recall', 'CVE recall'],
  ['vulnerability_identification_accuracy', 'Accuracy'],
] as const

function headline(metrics: any) {
  const hit = HEADLINE.find(([k]) => metrics?.[k] !== null && metrics?.[k] !== undefined)
  return hit ? { label: hit[1], value: metrics[hit[0]] as number } : null
}

function datasetIcon(d: any) {
  if (/injection/i.test(d.name)) return ShieldAlert
  return d.task_type === 'cve_matching' ? Database : Code2
}

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
  const series = (c: any) => `${modeLabel(c.mode)} · ${c.model}`
  const metricKeys = RATE_METRICS.filter((m) => configs.some((c: any) => c.metrics?.[m] !== undefined && c.metrics?.[m] !== null))
  const chartData = metricKeys.map((m) => ({ metric: titleCase(m).replace('Vulnerability Identification', 'Vuln ID'), ...Object.fromEntries(configs.map((c: any) => [series(c), c.metrics?.[m] !== null && c.metrics?.[m] !== undefined ? Math.round(c.metrics[m] * 1000) / 10 : null])) }))
  const selected = datasets.data?.find((d) => d.id === ds)
  const active = runs.data?.items.filter((r) => ['queued', 'running'].includes(r.status)).length || 0

  return (
    <div>
      <PageHeader title="AI evaluations" description="Benchmark TRACE's own agents on accuracy, false positives and negatives, groundedness, citation coverage, injection resistance, tool use, latency, tokens and cost." />

      <section aria-label="Benchmarks" className="mb-4 grid gap-3 md:grid-cols-3">
        {datasets.isLoading
          ? Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-[108px]" />)
          : (datasets.data || []).map((d) => {
              const Icon = datasetIcon(d)
              const on = d.id === ds
              return (
                <button
                  key={d.id}
                  type="button"
                  onClick={() => setDs(d.id)}
                  aria-pressed={on}
                  className={cn(
                    'group relative rounded-lg border bg-surface p-4 text-left shadow-sm transition-colors',
                    on ? 'border-primary/60 bg-primary/5 ring-1 ring-primary/40' : 'hover:border-foreground/20 hover:bg-accent/40',
                  )}
                >
                  <div className="flex items-start gap-3">
                    <span className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-md', on ? 'bg-primary/15 text-primary' : 'bg-muted text-muted-foreground group-hover:text-foreground')}>
                      <Icon className="h-[18px] w-[18px]" />
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold leading-tight">{d.name}</p>
                      <p className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">
                        {d.case_count} cases · {titleCase(d.task_type)}
                      </p>
                    </div>
                    {on && <Check className="ml-auto h-4 w-4 shrink-0 text-primary" />}
                  </div>
                  <p className="mt-3 line-clamp-2 text-xs text-muted-foreground">{d.description}</p>
                </button>
              )
            })}
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Run configuration" description={selected ? `On “${selected.name}”` : undefined} />
          <CardBody className="space-y-4">
            <div>
              <Label>Modes to compare</Label>
              <div className="space-y-2">
                {Object.entries(MODES).map(([m, meta]) => {
                  const on = modes.includes(m)
                  return (
                    <button
                      key={m}
                      type="button"
                      aria-pressed={on}
                      onClick={() => setModes(on ? modes.filter((x) => x !== m) : [...modes, m])}
                      className={cn('flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left transition-colors', on ? 'bg-accent/50' : 'opacity-60 hover:opacity-100')}
                      style={on ? { borderColor: `color-mix(in srgb, ${meta.color} 55%, transparent)` } : undefined}
                    >
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md" style={{ color: meta.color, background: `color-mix(in srgb, ${meta.color} 14%, transparent)` }}>
                        <meta.icon className="h-4 w-4" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium">{meta.label}</span>
                        <span className="block text-[11px] text-muted-foreground">{meta.detail}</span>
                      </span>
                      <span className={cn('flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border', on ? 'border-primary bg-primary text-primary-foreground' : 'border-muted-foreground/40')}>
                        {on && <Check className="h-3 w-3" />}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div><Label hint="blank = default">Model</Label><Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="qwen2.5-coder:7b" /></div>
              <div><Label hint="optional">Case limit</Label><Input type="number" min={1} value={limit} onChange={(e) => setLimit(e.target.value)} placeholder={selected ? `all ${selected.case_count}` : undefined} /></div>
            </div>
            <Button className="w-full" onClick={() => run.mutate()} loading={run.isPending} disabled={!ds || !modes.length}><Play /> Start {modes.length} run{modes.length === 1 ? '' : 's'}</Button>
            {active > 0 && <p className="text-center text-xs text-muted-foreground">{active} run{active === 1 ? '' : 's'} in progress, results update automatically</p>}
            {run.error ? <ErrorState error={run.error} /> : null}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Results" description={selected ? `Latest completed run per mode and model on “${selected.name}”` : undefined} />
          <CardBody>
            {configs.length ? (
              <>
                <div className="grid gap-3 sm:grid-cols-3">
                  {configs.map((c: any) => {
                    const meta = MODES[c.mode]
                    const h = headline(c.metrics)
                    return (
                      <button
                        key={c.run_id}
                        type="button"
                        onClick={() => router.push(`/evaluations/runs/${c.run_id}`)}
                        className="relative overflow-hidden rounded-md border bg-background/40 p-3 text-left transition-colors hover:bg-accent/40"
                      >
                        <span className="absolute inset-x-0 top-0 h-0.5" style={{ background: meta?.color }} />
                        <p className="text-xs font-medium" style={{ color: meta?.color }}>{modeLabel(c.mode)}</p>
                        <p className="tabular mt-1 text-2xl font-semibold tracking-tight">{h ? pct(h.value) : '—'}</p>
                        <p className="text-[11px] text-muted-foreground">{h ? h.label : 'No headline metric'}</p>
                        <p className="tabular mt-2 text-[11px] text-muted-foreground">
                          {c.metrics.cases} cases · p50 {c.metrics.latency_ms_p50 ? `${(c.metrics.latency_ms_p50 / 1000).toFixed(1)}s` : '—'}
                        </p>
                      </button>
                    )
                  })}
                  {(compare.data?.not_run || []).map((m: string) => (
                    <div key={m} className="flex flex-col justify-center rounded-md border border-dashed p-3 text-xs text-muted-foreground">
                      <p className="font-medium" style={{ color: MODES[m]?.color }}>{modeLabel(m)}</p>
                      <p className="mt-1">Not run yet</p>
                    </div>
                  ))}
                </div>
                <ResponsiveContainer width="100%" height={Math.max(220, metricKeys.length * 40)} className="mt-5">
                  <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 16 }} barGap={2}>
                    <CartesianGrid stroke="hsl(var(--border))" horizontal={false} />
                    <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="metric" width={150} tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: 'hsl(var(--muted) / 0.4)' }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
                    {configs.map((c: any) => (
                      <Bar key={series(c)} dataKey={series(c)} fill={MODES[c.mode]?.color || 'hsl(var(--primary))'} radius={[0, 4, 4, 0]} barSize={9} isAnimationActive={false} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
                <Table className="mt-4">
                  <THead><tr><Th>Configuration</Th><Th>Cases</Th><Th>Latency p50</Th><Th>Tokens</Th><Th>Est. cost</Th></tr></THead>
                  <tbody>
                    {configs.map((c: any) => (
                      <Tr key={c.run_id} onClick={() => router.push(`/evaluations/runs/${c.run_id}`)}>
                        <Td className="text-xs"><span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: MODES[c.mode]?.color }} />{modeLabel(c.mode)} · <span className="font-mono">{c.model}</span></Td>
                        <Td className="tabular text-xs">{c.metrics.cases}</Td>
                        <Td className="tabular text-xs">{c.metrics.latency_ms_p50 ? `${(c.metrics.latency_ms_p50 / 1000).toFixed(1)}s` : '—'}</Td>
                        <Td className="tabular text-xs">{c.metrics.tokens_in + c.metrics.tokens_out}</Td>
                        <Td className="tabular text-xs">{c.metrics.estimated_cost_usd === null ? 'n/a (local model)' : `$${c.metrics.estimated_cost_usd}`}</Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </>
            ) : (
              <div className="py-6">
                <EmptyState icon={BarChart3} title="No completed runs for this benchmark" description="Start a run to compare the three configurations side by side. Every number shown here comes from an executed run." />
                <div className="mx-auto mt-6 grid max-w-lg grid-cols-3 gap-2">
                  {Object.entries(MODES).map(([m, meta]) => (
                    <div key={m} className="rounded-md border border-dashed p-3 text-center">
                      <meta.icon className="mx-auto h-4 w-4" style={{ color: meta.color }} />
                      <p className="mt-1.5 text-xs font-medium">{meta.label}</p>
                      <p className="text-[11px] text-muted-foreground">Not run yet</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Evaluation history" description="Every run, newest first. Open a run for per-case results." />
        {runs.isLoading ? <Skeleton className="m-4 h-32" /> : runs.data?.items.length ? (
          <>
            <Table>
              <THead><tr><Th>Run</Th><Th>Benchmark</Th><Th>Mode</Th><Th>Model</Th><Th>Status</Th><Th>Score</Th><Th>Started</Th></tr></THead>
              <tbody>
                {runs.data.items.map((r) => {
                  const h = r.status === 'completed' ? headline(r.metrics) : null
                  return (
                    <Tr key={r.id} onClick={() => router.push(`/evaluations/runs/${r.id}`)}>
                      <Td className="max-w-[260px] truncate text-xs">{r.name}</Td>
                      <Td className="text-xs">{r.dataset_name}</Td>
                      <Td className="text-xs"><span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: MODES[r.mode]?.color }} />{modeLabel(r.mode)}</Td>
                      <Td className="font-mono text-xs">{r.model}</Td>
                      <Td><StatusBadge status={r.status} /></Td>
                      <Td className="tabular text-xs">{h ? <><span className="font-semibold">{pct(h.value)}</span> <span className="text-muted-foreground">{h.label.toLowerCase()}</span></> : <span className="text-muted-foreground">—</span>}</Td>
                      <Td className="text-xs text-muted-foreground">{ago(r.created_at)}</Td>
                    </Tr>
                  )
                })}
              </tbody>
            </Table>
            <Pagination page={runs.data.page} pages={runs.data.pages} total={runs.data.total} onPage={setPage} />
          </>
        ) : <EmptyState title="No evaluation runs yet" description="Runs you start appear here with their status and score." />}
      </Card>

      <Notice className="mt-4">Metrics appear only for runs that have actually executed. Configurations that were not run are labeled as such; no benchmark numbers are pre-filled.</Notice>
    </div>
  )
}
