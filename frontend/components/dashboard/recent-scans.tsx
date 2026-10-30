'use client'

import Link from 'next/link'
import { DemoBadge, StatusBadge } from '@/components/ui'
import { ago, shortSha } from '@/lib/utils'

export function RecentScans({ scans }: { scans: any[] }) {
  return (
    <ul className="divide-y">
      {scans.map((s) => (
        <li key={s.id}>
          <Link href={`/scans/${s.id}`} className="flex items-center justify-between gap-3 px-5 py-2.5 hover:bg-muted/40">
            <div className="min-w-0">
              <p className="flex items-center gap-2 truncate text-sm">
                {s.repository_name} {s.is_demo && <DemoBadge />}
              </p>
              <p className="font-mono text-[11px] text-muted-foreground">
                {shortSha(s.commit_sha)} · {s.trigger} · {ago(s.created_at)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              <span className="tabular text-xs text-muted-foreground">{s.total_findings} findings</span>
              <StatusBadge status={s.status} />
            </div>
          </Link>
        </li>
      ))}
    </ul>
  )
}
