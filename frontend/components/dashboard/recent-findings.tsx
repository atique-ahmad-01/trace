'use client'

import Link from 'next/link'
import { DemoBadge, SeverityBadge } from '@/components/ui'
import { ago } from '@/lib/utils'

export function RecentFindings({ findings }: { findings: any[] }) {
  return (
    <ul className="divide-y">
      {findings.map((f) => (
        <li key={f.id}>
          <Link href={`/vulnerabilities/${f.id}`} className="flex items-center gap-3 px-5 py-2.5 hover:bg-muted/40">
            <SeverityBadge severity={f.severity} className="w-[78px] justify-center" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm">{f.title}</p>
              <p className="truncate text-[11px] text-muted-foreground">
                {f.repository_name} · {f.vuln_id || f.file_path} · {f.scanner_name} · {ago(f.first_seen_at)}
              </p>
            </div>
            {f.is_demo && <DemoBadge />}
          </Link>
        </li>
      ))}
    </ul>
  )
}
