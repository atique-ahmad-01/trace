import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { formatDistanceToNowStrict } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'] as const
export type Severity = (typeof SEVERITIES)[number]

export const SEV_VAR: Record<string, string> = {
  CRITICAL: 'hsl(var(--sev-critical))',
  HIGH: 'hsl(var(--sev-high))',
  MEDIUM: 'hsl(var(--sev-medium))',
  LOW: 'hsl(var(--sev-low))',
  INFO: 'hsl(var(--sev-info))',
  UNKNOWN: 'hsl(var(--sev-info))',
}

export function formatDate(date?: string | null): string {
  if (!date) return '—'
  return new Date(date).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function ago(date?: string | null): string {
  if (!date) return '—'
  try {
    return `${formatDistanceToNowStrict(new Date(date))} ago`
  } catch {
    return '—'
  }
}

export function fmtNum(n?: number | null): string {
  return n === null || n === undefined ? '—' : new Intl.NumberFormat('en-US').format(n)
}

export function pct(v?: number | null, digits = 0): string {
  return v === null || v === undefined ? '—' : `${(v * 100).toFixed(digits)}%`
}

export function shortSha(sha?: string | null): string {
  if (!sha) return '—'
  return sha.startsWith('local-') ? `local·${sha.slice(6, 13)}` : sha.slice(0, 8)
}

export function titleCase(s?: string | null): string {
  return (s || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}
