'use client'

import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, ShieldCheck } from 'lucide-react'
import { Badge, Button, Card, CardBody, CardHeader, EmptyState, ErrorState, Input, Label, Modal, Notice, PageHeader, Pagination, Select, Skeleton, StatusBadge, THead, Table, Td, Textarea, Th, Tr } from '@/components/ui'
import { api, qs, type Paged } from '@/lib/api'
import { useRequireIntegration } from '@/lib/integrations'
import { ago, titleCase } from '@/lib/utils'

export default function AISecurityPage() {
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState(1)
  const catalog = useQuery({ queryKey: ['ais-catalog'], queryFn: () => api.get('/ai-security/catalog') })
  const list = useQuery<Paged<any>>({
    queryKey: ['assessments', page],
    queryFn: () => api.get(`/ai-security/assessments${qs({ page })}`),
    refetchInterval: (q) => ((q.state.data as any)?.items?.some((a: any) => ['queued', 'running'].includes(a.status)) ? 3000 : false),
  })
  return (
    <div>
      <PageHeader
        title="AI application security"
        description="Assess LLM apps and agent workflows for prompt injection, data leakage, unsafe tool use and insecure integrations."
        actions={<Button onClick={() => setOpen(true)}><Plus /> New assessment</Button>}
      />
      <Notice className="mb-4">A passing assessment never proves an AI system is secure — it only shows the listed tests did not demonstrate risk. Repository checks are heuristics requiring human review; endpoint probes are judged deterministically with a random canary.</Notice>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Assessments" />
          {list.isLoading ? <Skeleton className="m-4 h-40" /> : list.data?.items.length ? (
            <>
              <Table>
                <THead><tr><Th>Name</Th><Th>Target</Th><Th>Status</Th><Th>Failed / total</Th><Th>Risk</Th><Th>Created</Th></tr></THead>
                <tbody>
                  {list.data.items.map((a) => (
                    <Tr key={a.id} onClick={() => router.push(`/ai-security/${a.id}`)}>
                      <Td className="font-medium">{a.name}</Td>
                      <Td><Badge>{titleCase(a.target_type)}</Badge></Td>
                      <Td><StatusBadge status={a.status} /></Td>
                      <Td className="tabular text-xs">{a.status === 'completed' ? `${a.tests_failed} / ${a.total_tests}` : '—'}</Td>
                      <Td className="tabular text-xs">{a.risk_score ?? '—'}</Td>
                      <Td className="text-xs text-muted-foreground">{ago(a.created_at)}</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
              <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={setPage} />
            </>
          ) : <EmptyState icon={ShieldCheck} title="No assessments yet" description="Assess a repository's AI/agent code, or probe a live model endpoint with adversarial tests." action={<Button onClick={() => setOpen(true)}>New assessment</Button>} />}
        </Card>
        <Card className="h-fit">
          <CardHeader title="Test catalog" />
          <CardBody className="space-y-3 text-xs">
            {catalog.data ? (
              <>
                <p className="font-medium text-muted-foreground">Repository checks ({catalog.data.static_checks.length})</p>
                <ul className="space-y-1">{catalog.data.static_checks.map((c: any) => <li key={c.id}><span className="font-mono text-muted-foreground">{c.id}</span> {c.title}</li>)}</ul>
                <p className="pt-2 font-medium text-muted-foreground">Endpoint probes ({catalog.data.probes.length})</p>
                <ul className="space-y-1">{catalog.data.probes.map((c: any) => <li key={c.id}><span className="font-mono text-muted-foreground">{c.id}</span> {c.title}</li>)}</ul>
              </>
            ) : <Skeleton className="h-40" />}
          </CardBody>
        </Card>
      </div>
      <NewAssessment open={open} onClose={() => setOpen(false)} />
    </div>
  )
}

function NewAssessment({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const router = useRouter()
  const [type, setType] = useState('repository')
  const [name, setName] = useState('')
  const [repo, setRepo] = useState('')
  const llm = useRequireIntegration('model_provider')
  const [model, setModel] = useState('')
  const [system, setSystem] = useState('')
  const repos = useQuery({ queryKey: ['repositories'], queryFn: () => api.get('/repositories?page_size=100'), enabled: open })
  const m = useMutation({
    mutationFn: () => api.post('/ai-security/assessments', type === 'repository' ? { name, target_type: type, repository_id: repo } : { name, target_type: type, model: model || undefined, system_prompt: system || undefined }),
    onSuccess: (a: any) => { qc.invalidateQueries({ queryKey: ['assessments'] }); onClose(); router.push(`/ai-security/${a.id}`) },
  })
  return (
    <Modal open={open} onClose={onClose} title="New AI security assessment" wide footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={type === 'llm_endpoint' ? llm.guard(() => m.mutate()) : () => m.mutate()} loading={m.isPending} disabled={name.length < 3 || (type === 'repository' && !repo)}>Run assessment</Button></>}>
      <div className="space-y-3">
        <div><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Support agent — Q4 review" /></div>
        <div>
          <Label>Target</Label>
          <Select value={type} onChange={setType} className="w-full" options={[{ value: 'repository', label: 'Repository — static analysis of AI/agent code' }, { value: 'llm_endpoint', label: 'LLM endpoint — live adversarial probes' }]} />
        </div>
        {type === 'repository' ? (
          <div><Label>Repository</Label><Select value={repo} onChange={setRepo} placeholder="Select repository" className="w-full" options={(repos.data?.items || []).map((r: any) => ({ value: r.id, label: r.full_name }))} /></div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Provider</Label>
                <p className="flex h-9 items-center text-sm">{llm.item?.ready ? llm.item.fields.find((f) => f.name === 'provider')?.options?.find((o) => o.value === llm.item?.config.provider)?.label : <span className="text-muted-foreground">Not connected — set up in Settings → Integrations</span>}</p>
              </div>
              <div><Label hint="blank = configured model">Model</Label><Input value={model} onChange={(e) => setModel(e.target.value)} placeholder={llm.item?.config.model || 'qwen2.5-coder:7b'} /></div>
            </div>
            <div>
              <Label hint="use {canary} where a secret should be planted; blank = default support-agent prompt">System prompt under test</Label>
              <Textarea value={system} onChange={(e) => setSystem(e.target.value)} className="min-h-[120px] font-mono text-xs" />
            </div>
            <Notice>Probes are sent to your organization’s model provider. Do not paste real secrets — a random canary is generated per run.</Notice>
          </>
        )}
        {m.error ? <ErrorState error={m.error} /> : null}
      </div>
    </Modal>
  )
}
