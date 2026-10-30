'use client'

import * as React from 'react'
import Link from 'next/link'
import { cva, type VariantProps } from 'class-variance-authority'
import { AlertCircle, ChevronLeft, ChevronRight, Inbox, Loader2, X } from 'lucide-react'
import { cn, titleCase } from '@/lib/utils'

/* ------------------------------------------------------------------ Button */

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary/90',
        outline: 'border border-input bg-transparent hover:bg-accent',
        ghost: 'hover:bg-accent',
        destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
        subtle: 'bg-muted hover:bg-muted/80',
      },
      size: { default: 'h-9 px-4', sm: 'h-8 px-3 text-xs', lg: 'h-10 px-6', icon: 'h-9 w-9' },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  loading?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, loading, children, disabled, ...props }, ref) => (
  <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} disabled={disabled || loading} {...props}>
    {loading && <Loader2 className="animate-spin" />}
    {children}
  </button>
))
Button.displayName = 'Button'

export function LinkButton({ href, children, variant, size, className }: { href: string; children: React.ReactNode } & VariantProps<typeof buttonVariants> & { className?: string }) {
  return (
    <Link href={href} className={cn(buttonVariants({ variant, size }), className)}>
      {children}
    </Link>
  )
}

/* ------------------------------------------------------------------ Card */

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-lg border bg-surface shadow-sm', className)} {...props} />
}

export function CardHeader({ title, description, action, className }: { title: React.ReactNode; description?: React.ReactNode; action?: React.ReactNode; className?: string }) {
  return (
    <div className={cn('flex items-start justify-between gap-4 border-b px-5 py-4', className)}>
      <div className="min-w-0">
        <h3 className="text-sm font-semibold leading-none">{title}</h3>
        {description && <p className="mt-1.5 text-xs text-muted-foreground">{description}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

export function CardBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-5', className)} {...props} />
}

/* ------------------------------------------------------------------ Form controls */

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn('h-9 w-full rounded-md border border-input bg-background px-3 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50', className)}
    {...props}
  />
))
Input.displayName = 'Input'

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn('min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', className)}
    {...props}
  />
))
Textarea.displayName = 'Textarea'

export function Select({ value, onChange, options, className, placeholder, ...rest }: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  placeholder?: string
  className?: string
} & Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'>) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cn('h-9 rounded-md border border-input bg-background px-2.5 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', className)}
      {...rest}
    >
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

export function Label({ children, htmlFor, hint }: { children: React.ReactNode; htmlFor?: string; hint?: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1.5 block text-xs font-medium text-muted-foreground">
      {children}
      {hint && <span className="ml-1 font-normal opacity-70">— {hint}</span>}
    </label>
  )
}

export function Checkbox({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: React.ReactNode; disabled?: boolean }) {
  return (
    <label className={cn('inline-flex cursor-pointer select-none items-center gap-2 text-sm', disabled && 'cursor-not-allowed opacity-50')}>
      <input type="checkbox" className="h-4 w-4 accent-[hsl(var(--primary))]" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  )
}

export function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn('relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50', checked ? 'bg-primary' : 'bg-input')}
    >
      <span className={cn('inline-block h-4 w-4 rounded-full bg-background shadow transition-transform', checked ? 'translate-x-4' : 'translate-x-0.5')} />
    </button>
  )
}

/* ------------------------------------------------------------------ Badges */

const SEV_CLASS: Record<string, string> = {
  CRITICAL: 'bg-sev-critical/15 text-sev-critical ring-sev-critical/30',
  HIGH: 'bg-sev-high/15 text-sev-high ring-sev-high/30',
  MEDIUM: 'bg-sev-medium/15 text-sev-medium ring-sev-medium/30',
  LOW: 'bg-sev-low/15 text-sev-low ring-sev-low/30',
  INFO: 'bg-muted text-muted-foreground ring-border',
  UNKNOWN: 'bg-muted text-muted-foreground ring-border',
}

export function Badge({ children, className, tone = 'neutral', title }: { children: React.ReactNode; className?: string; tone?: 'neutral' | 'primary' | 'success' | 'warning' | 'danger'; title?: string }) {
  const tones = {
    neutral: 'bg-muted text-muted-foreground ring-border',
    primary: 'bg-primary/10 text-primary ring-primary/30',
    success: 'bg-success/10 text-success ring-success/30',
    warning: 'bg-warning/10 text-warning ring-warning/30',
    danger: 'bg-destructive/10 text-destructive ring-destructive/30',
  }
  return (
    <span title={title} className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset', tones[tone], className)}>
      {children}
    </span>
  )
}

export function SeverityBadge({ severity, className }: { severity?: string | null; className?: string }) {
  const s = (severity || 'UNKNOWN').toUpperCase()
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset', SEV_CLASS[s] || SEV_CLASS.UNKNOWN, className)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {s}
    </span>
  )
}

const STATUS_TONE: Record<string, 'neutral' | 'primary' | 'success' | 'warning' | 'danger'> = {
  COMPLETED: 'success', completed: 'success', passed: 'success', verified: 'success', connected: 'success', ok: 'success', RESOLVED: 'success', success: 'success', approved: 'primary', pr_opened: 'primary',
  RUNNING: 'primary', running: 'primary', PENDING: 'neutral', pending: 'neutral', queued: 'neutral', proposed: 'neutral', IN_PROGRESS: 'primary',
  PARTIAL: 'warning', partial: 'warning', verification_failed: 'warning', timeout: 'warning', unavailable: 'warning', skipped: 'neutral', not_applicable: 'neutral', needs_review: 'warning',
  FAILED: 'danger', failed: 'danger', error: 'danger', rejected: 'danger', denied: 'danger', OPEN: 'danger',
  FALSE_POSITIVE: 'neutral', ACCEPTED_RISK: 'neutral', demonstrated: 'danger',
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const s = status || 'unknown'
  const running = ['RUNNING', 'running', 'queued', 'PENDING', 'pending'].includes(s)
  return (
    <Badge tone={STATUS_TONE[s] || 'neutral'} className={className}>
      {running && <Loader2 className="h-3 w-3 animate-spin" />}
      {titleCase(s.toLowerCase())}
    </Badge>
  )
}

export function DemoBadge() {
  return (
    <Badge tone="warning" title="Sample/demo data from the bundled vulnerable fixture">
      Demo
    </Badge>
  )
}

/* ------------------------------------------------------------------ States */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-md bg-muted', className)} />
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('h-4 w-4 animate-spin text-muted-foreground', className)} />
}

export function EmptyState({ icon: Icon = Inbox, title, description, action, className }: { icon?: React.ElementType; title: string; description?: React.ReactNode; action?: React.ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
      <div className="mb-3 rounded-full bg-muted p-3">
        <Icon className="h-5 w-5 text-muted-foreground" />
      </div>
      <p className="text-sm font-medium">{title}</p>
      {description && <div className="mt-1 max-w-md text-xs text-muted-foreground">{description}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorState({ error, className }: { error: unknown; className?: string }) {
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div className={cn('flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive', className)}>
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      <span className="break-words">{msg}</span>
    </div>
  )
}

export function Notice({ tone = 'neutral', children, className }: { tone?: 'neutral' | 'warning' | 'success' | 'danger'; children: React.ReactNode; className?: string }) {
  const tones = {
    neutral: 'border-border bg-muted/40 text-muted-foreground',
    warning: 'border-warning/30 bg-warning/5 text-warning',
    success: 'border-success/30 bg-success/5 text-success',
    danger: 'border-destructive/30 bg-destructive/5 text-destructive',
  }
  return <div className={cn('rounded-md border px-3 py-2 text-xs', tones[tone], className)}>{children}</div>
}

/* ------------------------------------------------------------------ Layout helpers */

export function PageHeader({ title, description, actions, back }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; back?: { href: string; label: string } }) {
  return (
    <div className="mb-6">
      {back && (
        <Link href={back.href} className="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          <ChevronLeft className="h-3.5 w-3.5" /> {back.label}
        </Link>
      )}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {description && <div className="mt-1 text-sm text-muted-foreground">{description}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  )
}

export function KV({ items, className }: { items: [React.ReactNode, React.ReactNode][]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-sm', className)}>
      {items.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v ?? '—'}</dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

export function Stat({ label, value, sub, tone, icon: Icon }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string; icon?: React.ElementType }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
      </div>
      <p className="tabular mt-2 text-2xl font-semibold tracking-tight" style={tone ? { color: tone } : undefined}>
        {value}
      </p>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </Card>
  )
}

/* ------------------------------------------------------------------ Table */

export function Table({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('scrollbar-thin w-full overflow-x-auto', className)}>
      <table className="w-full text-sm">{children}</table>
    </div>
  )
}
export function THead({ children }: { children: React.ReactNode }) {
  return <thead className="border-b bg-muted/30 text-left text-xs font-medium text-muted-foreground">{children}</thead>
}
export function Th({ children, className }: { children?: React.ReactNode; className?: string }) {
  return <th className={cn('whitespace-nowrap px-4 py-2.5 font-medium', className)}>{children}</th>
}
export function Td({ children, className, colSpan, title }: { children?: React.ReactNode; className?: string; colSpan?: number; title?: string }) {
  return (
    <td colSpan={colSpan} title={title} className={cn('px-4 py-2.5 align-middle', className)}>
      {children}
    </td>
  )
}
export function Tr({ children, className, onClick }: { children: React.ReactNode; className?: string; onClick?: () => void }) {
  return (
    <tr onClick={onClick} className={cn('border-b last:border-0', onClick && 'cursor-pointer hover:bg-muted/40', className)}>
      {children}
    </tr>
  )
}

export function Pagination({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (p: number) => void }) {
  if (pages <= 1) return <div className="px-4 py-3 text-xs text-muted-foreground">{total} result{total === 1 ? '' : 's'}</div>
  return (
    <div className="flex items-center justify-between border-t px-4 py-2.5 text-xs text-muted-foreground">
      <span>
        {total} results · page {page} of {pages}
      </span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft />
        </Button>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight />
        </Button>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ Tabs */

export function Tabs({ tabs, value, onChange }: { tabs: { value: string; label: React.ReactNode }[]; value: string; onChange: (v: string) => void }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 border-b">
      {tabs.map((t) => (
        <button
          key={t.value}
          role="tab"
          aria-selected={value === t.value}
          onClick={() => onChange(t.value)}
          className={cn('-mb-px border-b-2 px-3 py-2 text-sm transition-colors', value === t.value ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ Modal */

export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: string; children: React.ReactNode; footer?: React.ReactNode; wide?: boolean }) {
  React.useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[10vh]" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title} className={cn('w-full rounded-lg border bg-surface shadow-xl', wide ? 'max-w-3xl' : 'max-w-lg')} onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b px-5 py-3.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-accent" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t px-5 py-3">{footer}</div>}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ Code */

export function CodeBlock({ code, className }: { code: string; className?: string }) {
  return <pre className={cn('scrollbar-thin overflow-x-auto rounded-md border bg-background p-3 font-mono text-xs leading-relaxed', className)}>{code}</pre>
}

export function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="scrollbar-thin overflow-x-auto rounded-md border bg-background py-2 font-mono text-xs leading-relaxed">
      {diff.split('\n').map((line, i) => (
        <div
          key={i}
          className={cn(
            'px-3',
            line.startsWith('+') && !line.startsWith('+++') && 'bg-success/10 text-success',
            line.startsWith('-') && !line.startsWith('---') && 'bg-destructive/10 text-destructive',
            line.startsWith('@@') && 'text-primary',
            (line.startsWith('+++') || line.startsWith('---')) && 'text-muted-foreground',
          )}
        >
          {line || ' '}
        </div>
      ))}
    </pre>
  )
}

export function ExtLink({ href, children }: { href?: string | null; children: React.ReactNode }) {
  if (!href) return <>{children}</>
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline-offset-2 hover:underline">
      {children}
    </a>
  )
}
