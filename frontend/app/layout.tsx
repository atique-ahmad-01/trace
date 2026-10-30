import './globals.css'
import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { AppShell } from '@/components/app-shell'
import { Providers } from '@/components/providers'

const sans = Inter({ subsets: ['latin'], variable: '--font-sans' })
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' })

export const metadata: Metadata = {
  title: 'TRACE — Trace Every Risk. Trust Every System.',
  description: 'AI-Powered Security & Compliance Intelligence. Threat · Risk · Analysis · Compliance · Evaluation.',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${sans.variable} ${mono.variable}`}>
      <body className="font-sans">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
