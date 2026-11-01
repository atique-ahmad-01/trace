import { useId } from 'react'
import { cn } from '@/lib/utils'

// The promise, used on the website, sign-in page, app sidebar, README and page metadata. Keep them in sync.
export const HEADLINE = ['Find real vulnerabilities.', 'Fix them only with your approval.'] as const
export const TAGLINE = HEADLINE.join(' ')
export const SUBTITLE = 'Open-source, self-hosted AI security for your repositories.'

/** The two-line promise; the second line carries the brand gradient. */
export function Headline({ className, as: Tag = 'h1' }: { className?: string; as?: 'h1' | 'h2' }) {
  return (
    <Tag className={cn('font-semibold tracking-tight', className)}>
      {HEADLINE[0]}
      <br />
      <span className="bg-gradient-to-r from-[hsl(var(--brand-from))] to-[hsl(var(--brand-to))] bg-clip-text text-transparent">{HEADLINE[1]}</span>
    </Tag>
  )
}

export const ACRONYM = [
  { letter: 'T', word: 'Threat', detail: 'Scanners and threat intelligence surface what can hurt you' },
  { letter: 'R', word: 'Risk', detail: 'Deterministic scoring from CVSS, KEV and reachability' },
  { letter: 'A', word: 'Analysis', detail: 'AI agents investigate with cited evidence' },
  { letter: 'C', word: 'Compliance', detail: 'Human approval and a full audit trail for every change' },
  { letter: 'E', word: 'Evaluation', detail: 'Fixes verified by re-scan; agents measured by benchmarks' },
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

/** Vertical T·R·A·C·E list: the letter in a quiet column, then the word and what it means. */
export function AcronymList({ className }: { className?: string }) {
  return (
    <ul className={cn('divide-y divide-border/70 border-y border-border/70', className)}>
      {ACRONYM.map((a) => (
        <li key={a.letter} className="flex items-baseline gap-5 py-3">
          <span className="w-4 shrink-0 font-mono text-sm font-semibold text-foreground">{a.letter}</span>
          <span>
            <span className="text-sm font-medium">{a.word}</span>
            <span className="ml-2 text-sm text-muted-foreground">{a.detail}</span>
          </span>
        </li>
      ))}
    </ul>
  )
}

/** Inline T·R·A·C·E: Threat · Risk · Analysis · Compliance · Evaluation, initials emphasized, no chrome. */
export function AcronymTags({ className }: { className?: string }) {
  return (
    <ul className={cn('flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground sm:gap-x-3 sm:text-sm', className)} aria-label="TRACE: Threat, Risk, Analysis, Compliance, Evaluation">
      {ACRONYM.map((a, i) => (
        <li key={a.letter} title={a.detail} className="flex items-center gap-2 sm:gap-3">
          {i > 0 && <span aria-hidden className="h-3 w-px bg-border" />}
          <span>
            <span className="font-semibold text-foreground">{a.letter}</span>
            {a.word.slice(1)}
          </span>
        </li>
      ))}
    </ul>
  )
}

/** Spaced T R A C E wordmark in the foreground color. */
export function Wordmark({ className }: { className?: string }) {
  return <span className={cn('font-bold tracking-[0.35em] text-foreground', className)}>TRACE</span>
}
