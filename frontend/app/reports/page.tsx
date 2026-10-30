'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, FileJson, FileText } from 'lucide-react'
import { Button, Card, CardBody, CardHeader, CodeBlock, ErrorState, Label, PageHeader, Select } from '@/components/ui'
import { api, download } from '@/lib/api'

type Kind = 'executive' | 'repository' | 'remediation' | 'ai-security' | 'evaluation'

const KINDS: { value: Kind; label: string; description: string }[] = [
  { value: 'executive', label: 'Executive summary', description: 'Posture score, severity mix, known-exploited exposure, top-risk repositories and priorities.' },
  { value: 'repository', label: 'Repository security report', description: 'Open findings, latest scan, scanner coverage and history for one repository.' },
  { value: 'remediation', label: 'Remediation report', description: 'All proposals with approval, verification and PR status.' },
  { value: 'ai-security', label: 'AI security assessment', description: 'Test results, evidence and mitigations for one assessment.' },
  { value: 'evaluation', label: 'Evaluation report', description: 'Metrics for one completed evaluation run.' },
]

export default function ReportsPage() {
  const [kind, setKind] = useState<Kind>('executive')
  const [target, setTarget] = useState('')
  const [includeDemo, setIncludeDemo] = useState('true')
  const [preview, setPreview] = useState<any>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const repos = useQuery({ queryKey: ['repositories'], queryFn: () => api.get('/repositories?page_size=100'), enabled: kind === 'repository' })
  const assessments = useQuery({ queryKey: ['assessments', 1], queryFn: () => api.get('/ai-security/assessments?page_size=100'), enabled: kind === 'ai-security' })
  const runs = useQuery({ queryKey: ['eval-runs-all'], queryFn: () => api.get('/evaluations/runs?page_size=100'), enabled: kind === 'evaluation' })
  const needsTarget = ['repository', 'ai-security', 'evaluation'].includes(kind)
  const path = (fmt: string) => {
    const base = kind === 'executive' ? `/reports/executive?include_demo=${includeDemo}&` : kind === 'remediation' ? '/reports/remediation?' : `/reports/${kind}/${target}?`
    return `${base}format=${fmt}`
  }
  const targets =
    kind === 'repository' ? (repos.data?.items || []).map((r: any) => ({ value: r.id, label: r.full_name }))
    : kind === 'ai-security' ? (assessments.data?.items || []).filter((a: any) => a.status === 'completed').map((a: any) => ({ value: a.id, label: a.name }))
    : kind === 'evaluation' ? (runs.data?.items || []).filter((r: any) => r.status === 'completed').map((r: any) => ({ value: r.id, label: r.name }))
    : []
  async function run(fmt: 'json' | 'pdf') {
    setError(null)
    setBusy(true)
    try {
      if (fmt === 'json') setPreview(await api.get(path('json')))
      else await download(path('pdf'), `trace-${kind}.pdf`)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div>
      <PageHeader title="Reports" description="Export security posture, vulnerability, AI security, remediation and evaluation reports as PDF or JSON." />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="h-fit">
          <CardHeader title="Generate report" />
          <CardBody className="space-y-4">
            <div className="space-y-2">
              {KINDS.map((k) => (
                <button key={k.value} onClick={() => { setKind(k.value); setTarget(''); setPreview(null) }} className={`w-full rounded-md border p-3 text-left transition-colors ${kind === k.value ? 'border-primary bg-primary/5' : 'hover:bg-accent'}`}>
                  <p className="text-sm font-medium">{k.label}</p>
                  <p className="text-xs text-muted-foreground">{k.description}</p>
                </button>
              ))}
            </div>
            {needsTarget && (
              <div>
                <Label>Target</Label>
                <Select value={target} onChange={setTarget} placeholder={targets.length ? 'Select' : 'Nothing available yet'} className="w-full" options={targets} />
              </div>
            )}
            {kind === 'executive' && (
              <div>
                <Label>Demo data</Label>
                <Select value={includeDemo} onChange={setIncludeDemo} className="w-full" options={[{ value: 'true', label: 'Include demo fixture findings' }, { value: 'false', label: 'Exclude demo data' }]} />
              </div>
            )}
            <div className="flex gap-2">
              <Button onClick={() => run('pdf')} disabled={busy || (needsTarget && !target)}><Download /> PDF</Button>
              <Button variant="outline" onClick={() => run('json')} disabled={busy || (needsTarget && !target)}><FileJson /> Preview JSON</Button>
            </div>
            {error ? <ErrorState error={error} /> : null}
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Preview" action={preview && <Button size="sm" variant="ghost" onClick={() => { const b = new Blob([JSON.stringify(preview, null, 2)], { type: 'application/json' }); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `trace-${kind}.json`; a.click(); URL.revokeObjectURL(u) }}><FileText /> Download JSON</Button>} />
          <CardBody>{preview ? <CodeBlock code={JSON.stringify(preview, null, 2)} className="max-h-[640px]" /> : <p className="text-sm text-muted-foreground">Choose a report and click “Preview JSON”.</p>}</CardBody>
        </Card>
      </div>
    </div>
  )
}
