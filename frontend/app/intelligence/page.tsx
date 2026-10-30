'use client'

import { useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BookOpen, RefreshCw, Search } from 'lucide-react'
import { Badge, Button, Card, CardBody, CardHeader, Checkbox, EmptyState, ErrorState, ExtLink, Input, KV, Label, Modal, Notice, PageHeader, Pagination, Skeleton, StatusBadge, THead, Table, Tabs, Td, Textarea, Th, Tr } from '@/components/ui'
import { useAuth } from '@/components/providers'
import { api, qs, type Paged } from '@/lib/api'
import { ago, formatDate } from '@/lib/utils'

function IntelInner() {
  const sp = useSearchParams()
  const [tab, setTab] = useState(sp.get('id') ? 'lookup' : 'lookup')
  return (
    <div>
      <PageHeader title="Vulnerability intelligence" description="Authoritative structured data (NVD, OSV, GHSA, CISA KEV) and the security RAG knowledge base used by agents." />
      <Tabs value={tab} onChange={setTab} tabs={[{ value: 'lookup', label: 'Lookup' }, { value: 'records', label: 'Tracked vulnerabilities' }, { value: 'kev', label: 'CISA KEV' }, { value: 'rag', label: 'RAG knowledge' }]} />
      {tab === 'lookup' && <Lookup initial={sp.get('id') || ''} />}
      {tab === 'records' && <Records />}
      {tab === 'kev' && <Kev />}
      {tab === 'rag' && <Rag />}
    </div>
  )
}

export default function IntelligencePage() {
  return (
    <Suspense>
      <IntelInner />
    </Suspense>
  )
}

function SourceBadges({ sources }: { sources: Record<string, any> }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {Object.entries(sources || {}).map(([k, v]: any) => (
        <Badge key={k} tone={v.status === 'ok' ? 'success' : ['not_found', 'skipped'].includes(v.status) ? 'neutral' : 'warning'} title={`${v.status} · ${v.fetched_at || ''}`}>
          {k}: {String(v.status).split(':')[0]}
        </Badge>
      ))}
    </div>
  )
}

function Lookup({ initial }: { initial: string }) {
  const [id, setId] = useState(initial)
  const [target, setTarget] = useState(initial)
  useEffect(() => {
    if (initial) {
      setId(initial)
      setTarget(initial)
    }
  }, [initial])
  const q = useQuery({ queryKey: ['intel', target], queryFn: () => api.get(`/intel/lookup/${encodeURIComponent(target)}`), enabled: !!target })
  const sources = useQuery({ queryKey: ['intel-sources'], queryFn: () => api.get('/intel/sources') })
  const r = q.data
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <Card className="p-4">
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); setTarget(id.trim()) }}>
            <Input value={id} onChange={(e) => setId(e.target.value)} placeholder="CVE-2021-44228, GHSA-…, PYSEC-…" aria-label="Vulnerability identifier" />
            <Button type="submit" loading={q.isFetching}>
              <Search /> Look up
            </Button>
          </form>
          <p className="mt-2 text-[11px] text-muted-foreground">Exact identifier lookups use structured APIs — never vector similarity. Results are cached for 24h.</p>
        </Card>
        {q.error ? <ErrorState error={q.error} /> : null}
        {r && (
          <Card>
            <CardHeader title={<span className="font-mono">{r.vuln_id}</span>} description={r.summary} action={r.is_known_exploited ? <Badge tone="danger">CISA KEV</Badge> : undefined} />
            <CardBody className="space-y-4">
              <SourceBadges sources={r.sources} />
              {r.description && <p className="whitespace-pre-line text-sm text-muted-foreground">{r.description.slice(0, 3000)}</p>}
              <KV
                items={[
                  ['Aliases', (r.aliases || []).join(', ') || '—'],
                  ['CVSS', r.cvss_score ? `${r.cvss_score} ${r.cvss_severity || ''}` : 'unavailable'],
                  ['Vector', <span key="v" className="font-mono text-xs">{r.cvss_vector || '—'}</span>],
                  ['CWE', (r.cwe_ids || []).join(', ') || '—'],
                  ['Published / modified', `${formatDate(r.published_at)} / ${formatDate(r.modified_at)}`],
                  ['Known exploited', r.is_known_exploited === null ? 'Unknown — KEV data unavailable' : r.is_known_exploited ? 'Yes' : 'Not listed in CISA KEV'],
                  ['Exploit references', r.exploit_references?.length ? r.exploit_references.map((u: string) => <div key={u}><ExtLink href={u}>{u}</ExtLink></div>) : 'none found'],
                  ['Fixed versions', (r.fixed_versions || []).join(', ') || 'none published'],
                  ['Your findings', r.affected_findings],
                ]}
              />
              {r.kev && <Notice tone="danger">KEV: {r.kev.name}. Added {r.kev.date_added}, due {r.kev.due_date}. Required action: {r.kev.required_action}</Notice>}
              {r.remediation && <Notice>{r.remediation}</Notice>}
              {r.affected?.length > 0 && (
                <div>
                  <p className="mb-1 text-xs font-medium text-muted-foreground">Affected packages / products</p>
                  <Table>
                    <THead><tr><Th>Ecosystem</Th><Th>Package / CPE</Th><Th>Introduced</Th><Th>Fixed</Th><Th>Source</Th></tr></THead>
                    <tbody>
                      {r.affected.slice(0, 20).map((a: any, i: number) => (
                        <Tr key={i}>
                          <Td className="text-xs">{a.ecosystem || '—'}</Td>
                          <Td className="font-mono text-xs">{a.package || a.criteria}</Td>
                          <Td className="font-mono text-xs">{(a.introduced || []).join(', ') || a.versionStartIncluding || '—'}</Td>
                          <Td className="font-mono text-xs text-success">{(a.fixed || []).join(', ') || a.versionEndExcluding || '—'}</Td>
                          <Td className="text-xs">{a.source}</Td>
                        </Tr>
                      ))}
                    </tbody>
                  </Table>
                </div>
              )}
              <details className="text-xs">
                <summary className="cursor-pointer text-muted-foreground">{r.references?.length || 0} references</summary>
                <ul className="mt-1 space-y-1">{(r.references || []).map((x: any) => <li key={x.url} className="truncate"><ExtLink href={x.url}>{x.url}</ExtLink> <span className="text-muted-foreground">[{x.source}{x.tags?.length ? ` · ${x.tags.filter(Boolean).join(', ')}` : ''}]</span></li>)}</ul>
              </details>
            </CardBody>
          </Card>
        )}
        {!target && <Card><EmptyState icon={Search} title="Look up any CVE or advisory" description="Aggregates NVD, OSV.dev, GitHub Security Advisories and the CISA KEV catalog with per-source status." /></Card>}
      </div>
      <Card className="h-fit">
        <CardHeader title="Intelligence sources" />
        <CardBody className="space-y-3">
          {sources.data ? (
            <>
              {sources.data.sources.map((s: any) => (
                <div key={s.key} className="text-sm">
                  <p className="font-medium">{s.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {s.mode}
                    {s.rate_limit ? ` · ${s.rate_limit}` : ''}
                    {s.entries !== undefined ? ` · ${s.entries} entries` : ''}
                    {s.sync?.last_synced_at ? ` · synced ${ago(s.sync.last_synced_at)}` : ''}
                  </p>
                </div>
              ))}
              <p className="border-t pt-2 text-xs text-muted-foreground">{sources.data.cached_records} cached vulnerability records</p>
            </>
          ) : (
            <Skeleton className="h-40" />
          )}
        </CardBody>
      </Card>
    </div>
  )
}

function Records() {
  const [page, setPage] = useState(1)
  const [kev, setKev] = useState(false)
  const recs = useQuery<Paged<any>>({ queryKey: ['intel-records', page, kev], queryFn: () => api.get(`/intel/records${qs({ page, kev: kev || undefined })}`) })
  return (
    <Card>
      <CardHeader title="Vulnerabilities affecting your repositories" description="Enriched identifiers referenced by findings" action={<Checkbox checked={kev} onChange={(v) => { setKev(v); setPage(1) }} label="Known exploited only" />} />
      {recs.isLoading ? <Skeleton className="m-4 h-40" /> : recs.data?.items.length ? (
        <>
          <Table>
            <THead><tr><Th>Identifier</Th><Th>Summary</Th><Th>CVSS</Th><Th>KEV</Th><Th>Fixed</Th><Th>Sources</Th></tr></THead>
            <tbody>
              {recs.data.items.map((r) => (
                <Tr key={r.vuln_id}>
                  <Td className="font-mono text-xs"><a href={`/intelligence?id=${encodeURIComponent(r.vuln_id)}`} className="text-primary hover:underline">{r.vuln_id}</a></Td>
                  <Td className="max-w-[360px] truncate text-xs">{r.summary || '—'}</Td>
                  <Td className="tabular text-xs">{r.cvss_score ?? '—'}</Td>
                  <Td>{r.is_known_exploited === null ? <Badge>unknown</Badge> : r.is_known_exploited ? <Badge tone="danger">yes</Badge> : <span className="text-xs text-muted-foreground">no</span>}</Td>
                  <Td className="max-w-[160px] truncate font-mono text-xs">{(r.fixed_versions || []).join(', ') || '—'}</Td>
                  <Td><SourceBadges sources={r.sources} /></Td>
                </Tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={recs.data.page} pages={recs.data.pages} total={recs.data.total} onPage={setPage} />
        </>
      ) : <EmptyState title="No enriched vulnerabilities yet" description="Enrichment runs automatically after scans that produce dependency findings." />}
    </Card>
  )
}

function Kev() {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const [term, setTerm] = useState('')
  const [page, setPage] = useState(1)
  const list = useQuery<Paged<any>>({ queryKey: ['kev', term, page], queryFn: () => api.get(`/intel/kev${qs({ q: term, page })}`) })
  const sync = useMutation({ mutationFn: () => api.post('/intel/kev/sync'), onSuccess: () => qc.invalidateQueries({ queryKey: ['kev'] }) })
  return (
    <Card>
      <CardHeader
        title="CISA Known Exploited Vulnerabilities"
        description={sync.data ? `Sync: ${sync.data.status} · ${sync.data.count} entries` : 'Catalog synchronized daily and on demand'}
        action={<Button size="sm" variant="outline" onClick={() => sync.mutate()} loading={sync.isPending}><RefreshCw /> Sync now</Button>}
      />
      <div className="border-b p-3">
        <form onSubmit={(e) => { e.preventDefault(); setTerm(q); setPage(1) }}><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search CVE, vendor, product" className="h-8 max-w-sm text-xs" /></form>
      </div>
      {sync.error ? <ErrorState error={sync.error} className="m-4" /> : null}
      {list.data?.items.length ? (
        <>
          <Table>
            <THead><tr><Th>CVE</Th><Th>Vendor / product</Th><Th>Name</Th><Th>Added</Th><Th>Due</Th><Th>Ransomware</Th></tr></THead>
            <tbody>
              {list.data.items.map((k) => (
                <Tr key={k.cve_id}>
                  <Td className="font-mono text-xs"><a className="text-primary hover:underline" href={`/intelligence?id=${k.cve_id}`}>{k.cve_id}</a></Td>
                  <Td className="text-xs">{k.vendor} / {k.product}</Td>
                  <Td className="max-w-[320px] truncate text-xs">{k.name}</Td>
                  <Td className="text-xs">{k.date_added}</Td>
                  <Td className="text-xs">{k.due_date}</Td>
                  <Td className="text-xs">{k.known_ransomware}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
          <Pagination page={list.data.page} pages={list.data.pages} total={list.data.total} onPage={setPage} />
        </>
      ) : list.isLoading ? <Skeleton className="m-4 h-40" /> : <EmptyState title="KEV catalog not synced" description="Click “Sync now” to download the catalog from cisa.gov." />}
    </Card>
  )
}

function Rag() {
  const qc = useQueryClient()
  const { role } = useAuth()
  const isAdmin = role === 'admin' || role === 'owner'
  const [query, setQuery] = useState('How do I prevent SQL injection in Python?')
  const [cwe, setCwe] = useState('')
  const [dense, setDense] = useState(true)
  const [kw, setKw] = useState(true)
  const [docOpen, setDocOpen] = useState(false)
  const stats = useQuery({ queryKey: ['rag-stats'], queryFn: () => api.get('/rag/stats'), refetchInterval: 10000 })
  const sources = useQuery<any[]>({ queryKey: ['rag-sources'], queryFn: () => api.get('/rag/sources'), refetchInterval: 10000 })
  const search = useMutation({ mutationFn: () => api.post('/rag/search', { query, cwe_ids: cwe ? cwe.split(',').map((c) => c.trim().toUpperCase()) : undefined, use_dense: dense, use_keyword: kw, top_k: 6 }) })
  const ingest = useMutation({ mutationFn: (s: string[]) => api.post('/rag/ingest', { sources: s }), onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['rag-sources'] }), 3000) })
  const s = stats.data
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <Card>
          <CardHeader title="Retrieval playground" description="Hybrid retrieval: dense vectors (Qdrant) + BM25, fused with reciprocal rank fusion, then reranked" />
          <CardBody className="space-y-3">
            <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); search.mutate() }}>
              <Input value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Query" />
              <div className="flex flex-wrap items-center gap-4">
                <Input value={cwe} onChange={(e) => setCwe(e.target.value)} placeholder="Filter: CWE-89, CWE-78" className="h-8 w-56 text-xs" aria-label="CWE filter" />
                <Checkbox checked={dense} onChange={setDense} label="Dense" />
                <Checkbox checked={kw} onChange={setKw} label="Keyword (BM25)" />
                <Button type="submit" size="sm" loading={search.isPending} disabled={!dense && !kw}><Search /> Search</Button>
              </div>
            </form>
            {search.error ? <ErrorState error={search.error} /> : null}
            {search.data && (
              <div className="space-y-2">
                <p className="text-[11px] text-muted-foreground">dense: {String(search.data.diagnostics.dense)} · keyword: {String(search.data.diagnostics.keyword)}</p>
                {search.data.evidence.length === 0 && <p className="text-sm text-muted-foreground">No evidence found.</p>}
                {search.data.evidence.map((e: any) => (
                  <div key={e.citation_id} className="rounded-md border p-3">
                    <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                      <span className="rounded bg-primary/10 px-1 font-mono text-primary">{e.citation_id}</span>
                      <span className="font-medium"><ExtLink href={e.url}>{e.title}</ExtLink></span>
                      <Badge>{e.source_type}</Badge>
                      <span className="text-muted-foreground">score {e.score} · {e.retrieval.join(' + ')}</span>
                    </div>
                    <p className="line-clamp-5 whitespace-pre-line text-xs text-muted-foreground">{e.text}</p>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>
      <div className="space-y-4">
        <Card>
          <CardHeader title="Knowledge base" />
          <CardBody>
            {s ? (
              <KV items={[['Documents', `${s.documents} (${s.embedded_documents} embedded)`], ['Chunks', s.chunks], ['Vectors', `${s.vectors} · ${s.vector_store} Qdrant`], ['Embedding model', <span key="m" className="font-mono text-xs">{s.embedding_model}</span>], ['Vector status', s.vector_status]]} />
            ) : <Skeleton className="h-24" />}
            {s?.embedding_error && <Notice tone="warning" className="mt-3">Embedding unavailable: {s.embedding_error}. Keyword retrieval still works.</Notice>}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Sources" action={isAdmin ? <Button size="sm" variant="outline" onClick={() => setDocOpen(true)}><BookOpen /> Add internal doc</Button> : undefined} />
          <ul className="divide-y text-sm">
            {(sources.data || []).map((src) => (
              <li key={src.id} className="px-5 py-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{src.name}</span>
                  <StatusBadge status={src.status} />
                </div>
                <p className="text-xs text-muted-foreground">{src.document_count} docs · {src.trust_level} · {src.last_ingested_at ? ago(src.last_ingested_at) : 'never'}</p>
                {src.detail && <p className="text-[11px] text-warning">{src.detail}</p>}
              </li>
            ))}
          </ul>
          {isAdmin && (
            <CardBody className="flex flex-wrap gap-2 border-t">
              <Button size="sm" variant="outline" onClick={() => ingest.mutate(['owasp'])} loading={ingest.isPending}>Ingest OWASP</Button>
              <Button size="sm" variant="outline" onClick={() => ingest.mutate(['cwe'])}>Ingest CWE</Button>
              <Button size="sm" variant="outline" onClick={() => ingest.mutate(['vuln_intel'])}>Index vuln intel</Button>
              <Button size="sm" variant="ghost" onClick={() => ingest.mutate(['reembed'])}>Re-embed missing</Button>
              {ingest.data && <p className="w-full text-[11px] text-muted-foreground">Queued: {ingest.data.queued.join(', ')}</p>}
            </CardBody>
          )}
        </Card>
      </div>
      <InternalDocModal open={docOpen} onClose={() => setDocOpen(false)} />
    </div>
  )
}

function InternalDocModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const m = useMutation({ mutationFn: () => api.post('/rag/documents', { title, content }), onSuccess: () => { qc.invalidateQueries({ queryKey: ['rag-sources'] }); qc.invalidateQueries({ queryKey: ['rag-stats'] }); onClose() } })
  return (
    <Modal open={open} onClose={onClose} title="Add approved internal security knowledge" wide footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button onClick={() => m.mutate()} loading={m.isPending} disabled={title.length < 3 || content.length < 20}>Ingest</Button></>}>
      <div className="space-y-3">
        <Notice>Internal documents are retrievable only within your organization and are labeled “approved_internal” in citations.</Notice>
        <div><Label>Title</Label><Input value={title} onChange={(e) => setTitle(e.target.value)} /></div>
        <div><Label hint="markdown supported">Content</Label><Textarea value={content} onChange={(e) => setContent(e.target.value)} className="min-h-[200px] font-mono text-xs" /></div>
        {m.error ? <ErrorState error={m.error} /> : null}
      </div>
    </Modal>
  )
}
