'use client'

import Link from 'next/link'
import { DemoBadge } from '@/components/ui'
import { SEV_VAR, ago } from '@/lib/utils'

export function SeverityStrip({ counts }: { counts: Record<string, number> }) {
  const keys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const total = keys.reduce((s, k) => s + (counts[k] || 0), 0)
  if (!total) return <div className="h-1.5 rounded-full bg-muted" />
  return (
    <div className="flex h-1.5 overflow-hidden rounded-full bg-muted" role="img" aria-label={keys.map((k) => `${counts[k] || 0} ${k.toLowerCase()}`).join(', ')}>
      {keys.map((k) => (counts[k] ? <div key={k} style={{ width: `${(counts[k] / total) * 100}%`, background: SEV_VAR[k] }} /> : null))}
    </div>
  )
}

export function MostVulnerableRepos({ repos }: { repos: any[] }) {
  return (
    <ul className="divide-y">
      {repos.map((r) => (
        <li key={r.id}>
          <Link href={`/repositories/${r.id}`} className="block px-5 py-3 hover:bg-muted/40">
            <div className="mb-1.5 flex items-center justify-between gap-3">
              <span className="flex min-w-0 items-center gap-2">
                <span className="truncate text-sm font-medium">{r.full_name}</span>
                {r.is_demo && <DemoBadge />}
              </span>
              <span className="tabular shrink-0 text-xs text-muted-foreground">
                score <span className="font-medium text-foreground">{r.security_score ?? '—'}</span> · {r.open} open
              </span>
            </div>
            <SeverityStrip counts={r.severity_counts} />
            <p className="mt-1.5 text-[11px] text-muted-foreground">Last scanned {ago(r.last_scanned_at)}</p>
          </Link>
        </li>
      ))}
    </ul>
  )
}
