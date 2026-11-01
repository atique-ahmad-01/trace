'use client'

import { useQuery } from '@tanstack/react-query'
import { Github, LogOut, Search } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { ExternalLink, REPO_URL } from '@/components/project-links'
import { useAuth } from '@/components/providers'
import { api, session } from '@/lib/api'
import { cn } from '@/lib/utils'

function ServiceDot({ ok, label, detail }: { ok: boolean | null; label: string; detail: string }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={detail}>
      <span className={cn('h-1.5 w-1.5 rounded-full', ok === null ? 'bg-muted-foreground' : ok ? 'bg-success' : 'bg-warning')} />
      {label}
    </span>
  )
}

export function Header() {
  const { me, logout, orgId } = useAuth()
  const router = useRouter()
  const [q, setQ] = useState('')
  const { data: status } = useQuery({ queryKey: ['system-status'], queryFn: () => api.get('/system/status'), enabled: !!orgId, refetchInterval: 60_000 })
  const org = me?.organizations.find((o) => o.id === orgId)
  const scannersUp = status ? status.scanners.filter((s: any) => s.available).length : 0
  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b bg-surface px-4 md:px-6">
      <form
        className="relative w-full max-w-md"
        onSubmit={(e) => {
          e.preventDefault()
          if (q.trim()) router.push(`/vulnerabilities?q=${encodeURIComponent(q.trim())}`)
        }}
      >
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search findings by CVE, package, file…"
          aria-label="Search findings"
          className="h-9 w-full rounded-md border border-input bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
      </form>
      <div className="flex items-center gap-5">
        {status && (
          <div className="hidden items-center gap-4 text-xs text-muted-foreground lg:flex">
            <ServiceDot ok={scannersUp === status.scanners.length} label={`Scanners ${scannersUp}/${status.scanners.length}`} detail={status.scanners.map((s: any) => `${s.name}: ${s.available ? s.version : 'unavailable'}`).join('\n')} />
            <ServiceDot ok={status.model_provider.status === 'ok' || status.model_provider.status === 'configured'} label={`Model: ${status.model_provider.model || status.model_provider.provider}`} detail={`${status.model_provider.provider} — ${status.model_provider.status}`} />
            <ServiceDot ok={status.rag.vectors > 0} label={`RAG ${status.rag.documents} docs`} detail={`${status.rag.vectors} vectors (${status.rag.vector_store})`} />
          </div>
        )}
        <ExternalLink href={REPO_URL} title="TRACE on GitHub" className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-foreground">
          <Github className="h-4 w-4" aria-label="TRACE on GitHub" />
        </ExternalLink>
        <div className="flex items-center gap-3 border-l pl-4">
          <div className="hidden text-right leading-tight sm:block">
            <p className="text-xs font-medium">{me?.user.full_name || me?.user.email}</p>
            {me && me.organizations.length > 1 ? (
              <select
                aria-label="Switch organization"
                value={orgId ?? ''}
                onChange={(e) => {
                  session.setOrg(e.target.value)
                  window.location.reload()
                }}
                className="max-w-[220px] cursor-pointer bg-transparent text-right text-[11px] text-muted-foreground hover:text-foreground focus-visible:outline-none"
              >
                {me.organizations.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} · {o.role}
                  </option>
                ))}
              </select>
            ) : (
              <p className="text-[11px] text-muted-foreground">
                {org?.name} · {org?.role}
              </p>
            )}
          </div>
          <button onClick={logout} className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label="Sign out" title="Sign out">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
