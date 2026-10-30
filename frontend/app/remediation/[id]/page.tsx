'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, GitPullRequest, ShieldCheck, X } from 'lucide-react'
import { useAuth } from '@/components/providers'
import { Badge, Button, Card, CardBody, CardHeader, DiffView, ErrorState, ExtLink, KV, Label, Notice, PageHeader, SeverityBadge, Skeleton, StatusBadge, Textarea } from '@/components/ui'
import { api } from '@/lib/api'
import { formatDate, titleCase } from '@/lib/utils'

export default function ProposalPage({ params }: { params: { id: string } }) {
  const qc = useQueryClient()
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const [comment, setComment] = useState('')
  const q = useQuery({
    queryKey: ['proposal', params.id],
    queryFn: () => api.get(`/remediation/proposals/${params.id}`),
    refetchInterval: (x) => ((x.state.data as any)?.verifications?.some((v: any) => ['pending', 'running'].includes(v.status)) ? 3000 : false),
  })
  const refresh = () => qc.invalidateQueries({ queryKey: ['proposal', params.id] })
  const decide = useMutation({ mutationFn: (decision: string) => api.post(`/remediation/proposals/${params.id}/decision`, { decision, comment: comment || undefined }), onSuccess: () => { setComment(''); refresh() } })
  const verify = useMutation({ mutationFn: () => api.post(`/remediation/proposals/${params.id}/verify`), onSuccess: refresh })
  const pr = useMutation({ mutationFn: () => api.post(`/remediation/proposals/${params.id}/pull-request`), onSuccess: refresh })
  if (q.error) return <ErrorState error={q.error} />
  if (!q.data) return <Skeleton className="h-96" />
  const p = q.data
  const f = p.finding
  const verifying = p.verifications.some((v: any) => ['pending', 'running'].includes(v.status))
  return (
    <div>
      <PageHeader
        back={{ href: '/remediation', label: 'Remediation' }}
        title={<span className="flex items-center gap-2">{p.title} <StatusBadge status={p.status} /></span>}
        description={<span className="flex flex-wrap items-center gap-2 text-xs"><SeverityBadge severity={f.severity} /><Link href={`/vulnerabilities/${f.id}`} className="text-primary hover:underline">{f.title}</Link> · {p.repository.full_name} · {titleCase(p.remediation_type)} · proposed by {p.proposed_by}</span>}
      />
      {(decide.error || verify.error || pr.error) && <ErrorState error={decide.error || verify.error || pr.error} className="mb-4" />}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Proposed change" description={p.files_changed?.length ? `Files: ${p.files_changed.join(', ')}` : 'Guidance only — no code change'} />
            <CardBody className="space-y-3 text-sm">
              {p.root_cause && <p><span className="text-muted-foreground">Root cause: </span>{p.root_cause}</p>}
              {p.description && <div className="whitespace-pre-line">{p.description}</div>}
              {p.side_effects && <Notice>Side effects / notes: {p.side_effects}</Notice>}
              {p.patch ? <DiffView diff={p.patch} /> : <Notice tone="warning">No patch was generated. Apply the steps manually; guidance-only proposals cannot be approved for automated application.</Notice>}
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Verification runs" description="Patch applied to an isolated snapshot; relevant scanners run before and after. Repository code (including tests) is never executed." />
            <CardBody className="space-y-4">
              {p.verifications.length === 0 && <p className="text-xs text-muted-foreground">Not verified yet.</p>}
              {p.verifications.map((v: any) => (
                <div key={v.id} className="rounded-md border p-3 text-sm">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">{formatDate(v.created_at)} · scanners: {(v.scanners || []).join(', ')}</span>
                    <StatusBadge status={v.status} />
                  </div>
                  {v.status !== 'pending' && v.status !== 'running' && (
                    <KV items={[
                      ['Patch applied', String(v.patch_applied ?? '—')],
                      ['Target before → after', `${v.target_finding_present_before ? 'present' : 'absent'} → ${v.target_finding_present_after === null ? '—' : v.target_finding_present_after ? 'present' : 'absent'}`],
                      ['Findings before → after', `${v.findings_before ?? '—'} → ${v.findings_after ?? '—'}`],
                      ['Resolved', (v.resolved_findings || []).map((r: any) => r.id).join(', ') || '—'],
                      ['New (regressions)', (v.new_findings || []).map((r: any) => `${r.severity} ${r.id}`).join(', ') || 'none'],
                      ['Tests', v.details?.tests],
                    ]} />
                  )}
                  {v.details?.reasons?.length > 0 && <ul className="mt-2 list-disc pl-5 text-xs text-warning">{v.details.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
                  {v.error_message && <ErrorState error={v.error_message} className="mt-2" />}
                </div>
              ))}
            </CardBody>
          </Card>
        </div>
        <div className="space-y-4">
          <Card>
            <CardHeader title="Workflow" />
            <CardBody className="space-y-4">
              <KV items={[['Evidence', p.evidence_sufficient ? <Badge key="e" tone="success">sufficient</Badge> : <Badge key="e" tone="warning">insufficient</Badge>], ['Confidence', p.confidence || '—'], ['Base commit', <span key="b" className="font-mono text-xs">{p.base_commit?.slice(0, 12) || '—'}</span>], ['Pull request', p.pr_url ? <ExtLink key="p" href={p.pr_url}>#{p.pr_number}</ExtLink> : '—']]} />
              {isAdmin && ['proposed', 'verification_failed', 'verified'].includes(p.status) && p.status !== 'verified' && (
                <div className="space-y-2 border-t pt-4">
                  <Label hint={!p.evidence_sufficient ? 'required: evidence is insufficient' : 'optional'}>Review comment</Label>
                  <Textarea value={comment} onChange={(e) => setComment(e.target.value)} />
                  <div className="flex gap-2">
                    <Button onClick={() => decide.mutate('approved')} loading={decide.isPending && decide.variables === 'approved'} disabled={!p.patch}><Check /> Approve</Button>
                    <Button variant="outline" onClick={() => decide.mutate('rejected')} loading={decide.isPending && decide.variables === 'rejected'}><X /> Reject</Button>
                  </div>
                </div>
              )}
              {p.patch && ['approved', 'verified', 'verification_failed', 'pr_opened'].includes(p.status) && (
                <Button variant="outline" className="w-full" onClick={() => verify.mutate()} loading={verify.isPending} disabled={verifying}><ShieldCheck /> {verifying ? 'Verifying…' : 'Run verification'}</Button>
              )}
              {isAdmin && p.patch && p.repository.provider === 'github' && ['approved', 'verified'].includes(p.status) && (
                <Button className="w-full" onClick={() => pr.mutate()} loading={pr.isPending}><GitPullRequest /> Open pull request</Button>
              )}
              {p.repository.provider !== 'github' && p.patch && <p className="text-[11px] text-muted-foreground">Pull requests require a GitHub-connected repository.</p>}
              {!isAdmin && <p className="text-[11px] text-muted-foreground">Approvals and pull requests require the admin role.</p>}
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Approval history" />
            <CardBody className="space-y-2 text-sm">
              {p.approvals.length ? p.approvals.map((a: any) => (
                <div key={a.id}>
                  <p className="flex items-center gap-2"><StatusBadge status={a.decision} /> <span className="text-xs">{a.user_email}</span></p>
                  <p className="text-xs text-muted-foreground">{formatDate(a.created_at)}{a.comment ? ` — ${a.comment}` : ''}</p>
                </div>
              )) : <p className="text-xs text-muted-foreground">No decisions yet.</p>}
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  )
}
