import './globals.css'
import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { AppShell } from '@/components/app-shell'
import { Providers } from '@/components/providers'
import { THEME_BOOT_SCRIPT } from '@/lib/theme'

const sans = Inter({ subsets: ['latin'], variable: '--font-sans' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' })

export const metadata: Metadata = {
  title: 'TRACE — Find real vulnerabilities. Fix them only with your approval.',
  description: 'Open-source, self-hosted AI security for your repositories: real scanners, AI investigations with cited evidence, and fixes verified by re-scanning.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    // The theme class is set by THEME_BOOT_SCRIPT before paint, so the server and client markup differ on <html>.
    <html lang="en" className={`${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="font-sans">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
