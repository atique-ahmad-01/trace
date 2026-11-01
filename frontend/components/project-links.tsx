import { BookOpen, Github, Terminal } from 'lucide-react'
import { cn } from '@/lib/utils'

/** TRACE is open source: links to the code, the docs and the local setup guide. */
export const REPO_URL = 'https://github.com/atique-ahmad-01/trace'
export const DOCS_URL = `${REPO_URL}#readme`
export const LOCAL_SETUP_URL = `${REPO_URL}#-quick-start`
export const ARCHITECTURE_URL = `${REPO_URL}/blob/main/docs/ARCHITECTURE.md`

export const PROJECT_LINKS = [
  { name: 'GitHub', href: REPO_URL, icon: Github, title: 'Source code on GitHub' },
  { name: 'Documentation', href: DOCS_URL, icon: BookOpen, title: 'Features, configuration and security model' },
  { name: 'Run locally', href: LOCAL_SETUP_URL, icon: Terminal, title: 'Set up TRACE on your machine with all scanners' },
]

export function ExternalLink({ href, className, title, children }: { href: string; className?: string; title?: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" title={title} className={className}>
      {children}
    </a>
  )
}

/** Vertical list for the sidebar footer. */
export function ProjectLinksList({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-0.5', className)}>
      {PROJECT_LINKS.map((l) => (
        <ExternalLink
          key={l.href}
          href={l.href}
          title={l.title}
          className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          <l.icon className="h-4 w-4" />
          {l.name}
        </ExternalLink>
      ))}
    </div>
  )
}

/** Inline row of links, e.g. under the sign-in form. */
export function ProjectLinksRow({ className }: { className?: string }) {
  return (
    <div className={cn('flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-xs text-muted-foreground', className)}>
      {PROJECT_LINKS.map((l) => (
        <ExternalLink key={l.href} href={l.href} title={l.title} className="inline-flex items-center gap-1.5 hover:text-foreground">
          <l.icon className="h-3.5 w-3.5" />
          {l.name}
        </ExternalLink>
      ))}
    </div>
  )
}
