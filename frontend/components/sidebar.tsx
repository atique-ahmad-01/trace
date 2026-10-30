'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  AlertTriangle,
  BarChart3,
  Bot,
  Database,
  FileText,
  FolderGit2,
  LayoutDashboard,
  Plug,
  ScanSearch,
  Settings,
  ShieldCheck,
  Wrench,
} from 'lucide-react'
import { Logo, SUBTITLE, TAGLINE, Wordmark } from '@/components/brand'
import { cn } from '@/lib/utils'

const sections = [
  {
    label: 'Monitor',
    items: [
      { name: 'Overview', href: '/', icon: LayoutDashboard },
      { name: 'Repositories', href: '/repositories', icon: FolderGit2 },
      { name: 'Scans', href: '/scans', icon: ScanSearch },
      { name: 'Vulnerabilities', href: '/vulnerabilities', icon: AlertTriangle },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { name: 'AI Investigations', href: '/investigations', icon: Bot },
      { name: 'Vulnerability Intel', href: '/intelligence', icon: Database },
      { name: 'AI Security', href: '/ai-security', icon: ShieldCheck },
      { name: 'MCP Integrations', href: '/mcp', icon: Plug },
    ],
  },
  {
    label: 'Act',
    items: [
      { name: 'Remediation', href: '/remediation', icon: Wrench },
      { name: 'Evaluations', href: '/evaluations', icon: BarChart3 },
      { name: 'Reports', href: '/reports', icon: FileText },
      { name: 'Settings', href: '/settings', icon: Settings },
    ],
  },
]

export function Sidebar() {
  const pathname = usePathname()
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r bg-surface md:flex">
      <div className="flex h-14 items-center gap-2.5 border-b px-5">
        <Logo className="h-8 w-8" />
        <Wordmark className="text-base" />
      </div>
      <nav className="scrollbar-thin flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Main">
        {sections.map((s) => (
          <div key={s.label}>
            <p className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">{s.label}</p>
            <div className="space-y-0.5">
              {s.items.map((item) => {
                const active = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      'flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors',
                      active ? 'bg-primary/10 font-medium text-primary' : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                    )}
                  >
                    <item.icon className="h-4 w-4" />
                    {item.name}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t px-5 py-3 leading-snug">
        <p className="text-[11px] font-medium">{TAGLINE}</p>
        <p className="text-[10px] text-muted-foreground">{SUBTITLE}</p>
      </div>
    </aside>
  )
}
