'use client'

import { SEV_VAR, fmtNum } from '@/lib/utils'

export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const keys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const max = Math.max(1, ...keys.map((k) => counts[k] || 0))
  return (
    <div className="space-y-3">
      {keys.map((k) => (
        <div key={k}>
          <div className="mb-1 flex items-center justify-between text-xs">
            <span className="text-muted-foreground">{k.charAt(0) + k.slice(1).toLowerCase()}</span>
            <span className="tabular font-medium">{fmtNum(counts[k] || 0)}</span>
          </div>
          <div className="h-2 rounded-full bg-muted">
            <div className="h-2 rounded-full" style={{ width: `${((counts[k] || 0) / max) * 100}%`, background: SEV_VAR[k] }} />
          </div>
        </div>
      ))}
    </div>
  )
}

export function PostureGauge({ score }: { score: number | null }) {
  const r = 38
  const c = 2 * Math.PI * r
  const v = score ?? 0
  const color = score === null ? 'hsl(var(--muted-foreground))' : v >= 80 ? 'hsl(var(--success))' : v >= 50 ? 'hsl(var(--sev-medium))' : 'hsl(var(--sev-critical))'
  return (
    <div className="relative h-24 w-24">
      <svg viewBox="0 0 100 100" className="h-24 w-24 -rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="8" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(v / 100) * c} ${c}`} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tabular text-xl font-semibold">{score === null ? '—' : Math.round(v)}</span>
        <span className="text-[10px] text-muted-foreground">/ 100</span>
      </div>
    </div>
  )
}
