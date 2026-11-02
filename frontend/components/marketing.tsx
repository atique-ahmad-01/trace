'use client'

import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

// Building blocks for the landing and login pages, matching the demo video's look:
// heavy display type, thick borders with hard offset shadows, drifting line doodles, grid and slash backgrounds.

export type DoodleKind = 'doc' | 'bug' | 'warn' | 'shield' | 'lock' | 'search' | 'check' | 'code' | 'folder' | 'question'

const PATHS: Record<DoodleKind, React.ReactNode> = {
  doc: (<><path d="M14 6h22l10 10v30H14z" /><path d="M36 6v10h10" /><path d="M20 24h18M20 31h18M20 38h12" /></>),
  bug: (<><ellipse cx="30" cy="32" rx="11" ry="14" /><path d="M30 18v28M19 26h-8M41 26h8M19 36h-8M41 36h8M23 16l-4-6M37 16l4-6" /></>),
  warn: (<><path d="M30 8 L52 48 H8 Z" /><path d="M30 22v13M30 41v1" /></>),
  shield: (<><path d="M30 6 L50 13 V29 C50 42 41 51 30 55 C19 51 10 42 10 29 V13 Z" /><path d="M21 30l6 6 12-13" /></>),
  lock: (<><rect x="13" y="26" width="34" height="24" rx="4" /><path d="M20 26v-7a10 10 0 0 1 20 0v7M30 35v6" /></>),
  search: (<><circle cx="26" cy="26" r="13" /><path d="M36 36l12 12" /></>),
  check: (<><circle cx="30" cy="30" r="20" /><path d="M20 30l7 7 13-14" /></>),
  code: (<><rect x="8" y="12" width="44" height="36" rx="4" /><path d="M24 24l-6 6 6 6M36 24l6 6-6 6" /></>),
  folder: (<><path d="M8 18h16l5 6h23v24H8z" /></>),
  question: (<><path d="M10 12h40v28H30l-10 9v-9H10z" /><path d="M25 21a5 5 0 1 1 6 5v3M31 34v1" /></>),
}

export function Doodle({ kind, className, strokeWidth = 3 }: { kind: DoodleKind; className?: string; strokeWidth?: number }) {
  return (
    <svg viewBox="0 0 60 60" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      {PATHS[kind]}
    </svg>
  )
}

type Spot = { kind: DoodleKind; top: string; left: string; size?: number; r?: number }

/** Doodles scattered around a section's edges, each drifting on its own slow loop. */
export function DoodleField({ spots, className }: { spots: Spot[]; className?: string }) {
  return (
    <div aria-hidden className={cn('pointer-events-none absolute inset-0 overflow-hidden', className)}>
      {spots.map((s, i) => (
        <div
          key={i}
          className="m-float absolute"
          style={{ top: s.top, left: s.left, width: s.size ?? 52, height: s.size ?? 52, ['--r' as string]: `${s.r ?? (i % 2 ? 12 : -10)}deg`, ['--dur' as string]: `${8 + (i % 5) * 1.7}s`, ['--delay' as string]: `${-i * 1.3}s`, ['--dx' as string]: `${i % 2 ? 12 : -10}px`, ['--dy' as string]: `${i % 3 ? -14 : 12}px` }}
        >
          <Doodle kind={s.kind} className="h-full w-full" />
        </div>
      ))}
    </div>
  )
}

/** Fades and lifts its children in the first time they scroll into view. */
export function Reveal({ children, className, delay = 0, as: Tag = 'div' }: { children: React.ReactNode; className?: string; delay?: number; as?: 'div' | 'li' }) {
  const ref = useRef<HTMLElement | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (typeof IntersectionObserver === 'undefined') return el.classList.add('m-in')
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) {
          el.classList.add('m-in')
          io.disconnect()
        }
      },
      { rootMargin: '0px 0px -10% 0px' },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [])
  return (
    <Tag ref={ref as never} className={cn('m-reveal', className)} style={{ transitionDelay: `${delay}ms` }}>
      {children}
    </Tag>
  )
}

/** The end-card treatment: a tilted teal bar with an offset shadow behind a phrase. */
export function HighlightBar({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn('relative inline-block -rotate-[1.5deg] rounded-lg bg-m-teal px-3 text-[#0b1f1d] md:px-4', className)} style={{ boxShadow: '6px 6px 0 rgb(var(--m-shadow))' }}>
      {children}
    </span>
  )
}

export function Pill({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center gap-1.5 rounded-full border-2 border-m-ink bg-m-card px-3 py-1 font-mono text-xs font-semibold text-m-ink', className)}>{children}</span>
}

/** Browser chrome with a URL and a teal tag, like the "real app" scenes in the video. */
export function BrowserFrame({ url, tag, children, className }: { url: string; tag?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('m-card overflow-hidden', className)}>
      <div className="flex items-center gap-2 border-b-[3px] border-m-ink bg-m-card px-3 py-2.5 md:px-4">
        <span className="h-3 w-3 rounded-full border-2 border-m-ink" />
        <span className="h-3 w-3 rounded-full border-2 border-m-ink" />
        <span className="h-3 w-3 rounded-full border-2 border-m-ink" />
        <span className="ml-2 min-w-0 flex-1 truncate rounded-full border-2 border-m-ink px-3 py-0.5 font-mono text-[11px] text-m-ink md:max-w-md">{url}</span>
        {tag && <span className="hidden rounded-md bg-m-teal px-2.5 py-0.5 font-display text-sm font-extrabold text-[#0b1f1d] sm:inline">{tag}</span>}
      </div>
      {children}
    </div>
  )
}

/** Dark terminal window. */
export function Terminal({ title = 'bash', children, className, action }: { title?: string; children: React.ReactNode; className?: string; action?: React.ReactNode }) {
  return (
    <div className={cn('overflow-hidden rounded-2xl border-[3px] border-[#05110f] bg-[#13201f] text-left shadow-2xl', className)}>
      <div className="flex items-center gap-2 border-b-2 border-[#05110f] bg-[#1b2a28] px-4 py-2.5">
        <span className="h-3 w-3 rounded-full border-2 border-[#56706c]" />
        <span className="h-3 w-3 rounded-full border-2 border-[#56706c]" />
        <span className="h-3 w-3 rounded-full border-2 border-[#56706c]" />
        <span className="ml-2 font-mono text-xs text-[#8fb0aa]">{title}</span>
        <span className="ml-auto">{action}</span>
      </div>
      {children}
    </div>
  )
}

/** Big two-tone section heading: an eyebrow, then display type. */
export function SectionHeading({ eyebrow, title, accent, children, className, dark }: { eyebrow: string; title: React.ReactNode; accent?: React.ReactNode; children?: React.ReactNode; className?: string; dark?: boolean }) {
  return (
    <Reveal className={cn('mx-auto mb-10 max-w-3xl text-center md:mb-14', className)}>
      <p className={cn('font-mono text-xs font-bold uppercase tracking-[0.25em]', dark ? 'text-m-teal' : 'text-m-tealdeep')}>{eyebrow}</p>
      <h2 className={cn('m-display mt-3 text-4xl md:text-6xl', dark ? 'text-[#fbfdfc]' : 'text-m-ink')}>
        {title}
        {accent && <span className={dark ? 'text-m-teal' : 'text-m-tealdeep'}> {accent}</span>}
      </h2>
      {children && <p className={cn('mx-auto mt-4 max-w-2xl text-base md:text-lg', dark ? 'text-[#a9c9c2]' : 'text-m-muted')}>{children}</p>}
    </Reveal>
  )
}
