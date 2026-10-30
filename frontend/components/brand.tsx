import { useId } from 'react'
import { cn } from '@/lib/utils'

export const TAGLINE = 'Trace Every Risk. Trust Every System.'
export const SUBTITLE = 'AI-Powered Security & Compliance Intelligence'

export const ACRONYM = [
  { letter: 'T', word: 'Threat', color: 'hsl(186 85% 50%)', detail: 'Scanners and threat intelligence surface what can hurt you' },
  { letter: 'R', word: 'Risk', color: 'hsl(217 91% 60%)', detail: 'Deterministic scoring from CVSS, KEV and reachability' },
  { letter: 'A', word: 'Analysis', color: 'hsl(258 90% 66%)', detail: 'AI agents investigate with cited evidence' },
  { letter: 'C', word: 'Compliance', color: 'hsl(330 81% 60%)', detail: 'Human approval and a full audit trail for every change' },
  { letter: 'E', word: 'Evaluation', color: 'hsl(160 84% 39%)', detail: 'Fixes verified by re-scan; agents measured by benchmarks' },
]

export function Logo({ className }: { className?: string }) {
  // Unique per instance: a shared id resolves to the first <defs>, which breaks when that copy is display:none.
  const gradientId = `trace-logo-${useId().replace(/:/g, '')}`
  return (
    <svg viewBox="0 0 64 72" className={className} aria-hidden>
      <defs>
        <linearGradient id={gradientId} x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="hsl(186 85% 50%)" />
          <stop offset="1" stopColor="hsl(217 91% 60%)" />
        </linearGradient>
      </defs>
      <path d="M32 3 L59 12 V33 C59 52 47 65 32 70 C17 65 5 52 5 33 V12 Z" fill="hsl(186 85% 50% / 0.1)" stroke={`url(#${gradientId})`} strokeWidth="4" strokeLinejoin="round" />
      <circle cx="30" cy="34" r="11" fill="none" stroke="hsl(186 85% 55%)" strokeWidth="4" />
      <path d="M38.5 42.5 L46 50" stroke="hsl(186 85% 55%)" strokeWidth="4.5" strokeLinecap="round" />
    </svg>
  )
}

/** Vertical T·R·A·C·E list with words and short descriptions. */
export function AcronymList({ className }: { className?: string }) {
  return (
    <ul className={cn('space-y-3', className)}>
      {ACRONYM.map((a) => (
        <li key={a.letter} className="flex items-start gap-4">
          <span
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-lg font-bold ring-1 ring-inset"
            style={{ color: a.color, background: `color-mix(in srgb, ${a.color} 14%, transparent)`, boxShadow: `0 0 18px -6px ${a.color}` }}
          >
            {a.letter}
          </span>
          <span className="pt-0.5">
            <span className="block text-base font-semibold tracking-tight">{a.word}</span>
            <span className="block text-xs text-muted-foreground">{a.detail}</span>
          </span>
        </li>
      ))}
    </ul>
  )
}

/** Row of colored pill tags: [T Threat] [R Risk] ... */
export function AcronymTags({ className }: { className?: string }) {
  return (
    <ul className={cn('flex flex-wrap gap-2', className)}>
      {ACRONYM.map((a) => (
        <li
          key={a.letter}
          title={a.detail}
          className="inline-flex items-center gap-1.5 rounded-full py-1 pl-1 pr-3 text-xs font-medium ring-1 ring-inset"
          style={{ color: a.color, background: `color-mix(in srgb, ${a.color} 10%, transparent)`, ['--tw-ring-color' as string]: `color-mix(in srgb, ${a.color} 35%, transparent)` }}
        >
          <span
            className="flex h-5 w-5 items-center justify-center rounded-full text-[11px] font-bold text-background"
            style={{ background: a.color }}
          >
            {a.letter}
          </span>
          {a.word}
        </li>
      ))}
    </ul>
  )
}

/** Spaced T R A C E wordmark in the foreground color. */
export function Wordmark({ className }: { className?: string }) {
  return <span className={cn('font-bold tracking-[0.35em] text-foreground', className)}>TRACE</span>
}
