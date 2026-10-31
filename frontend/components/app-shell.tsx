'use client'

import { usePathname } from 'next/navigation'
import { Header } from '@/components/header'
import { IntegrationBanner, IntegrationPrompt } from '@/components/integration-prompt'
import { Sidebar } from '@/components/sidebar'

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  if (pathname.startsWith('/login')) return <>{children}</>
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header />
        <IntegrationBanner />
        <main className="scrollbar-thin flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1400px] px-4 py-6 md:px-8">{children}</div>
        </main>
      </div>
      <IntegrationPrompt />
    </div>
  )
}
