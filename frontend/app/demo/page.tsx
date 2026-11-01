'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Github } from 'lucide-react'
import { Logo, SUBTITLE, TAGLINE, Wordmark } from '@/components/brand'
import { ExternalLink, ProjectLinksRow, REPO_URL } from '@/components/project-links'
import { cn } from '@/lib/utils'

const VIDEOS = [
  {
    id: 'full',
    label: 'Product demo',
    length: '2 min',
    src: '/demo/trace-demo.mp4',
    description:
      'Narrated walkthrough of the real product: connecting a model provider and GitHub, a scan with four scanners, live vulnerability intelligence, an AI investigation with cited evidence, and a human-approved fix verified by re-scanning.',
  },
  { id: 'short', label: 'Quick cut', length: '30 sec', src: '/demo/trace-demo-30s.mp4', description: 'The whole flow from scan to verified fix in thirty seconds.' },
  { id: 'arch', label: 'Architecture', length: 'animation', src: '/demo/trace-architecture.mp4', description: 'How scanners, vulnerability intelligence, AI agents and remediation fit together.' },
]

export default function DemoPage() {
  const [active, setActive] = useState(VIDEOS[0].id)
  const video = VIDEOS.find((v) => v.id === active) ?? VIDEOS[0]

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b bg-surface">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between gap-4 px-4">
          <Link href="/demo" className="flex items-center gap-2.5">
            <Logo className="h-8 w-8" />
            <Wordmark className="text-base" />
          </Link>
          <div className="flex items-center gap-2">
            <ExternalLink href={REPO_URL} title="TRACE on GitHub" className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm text-muted-foreground hover:bg-accent hover:text-foreground">
              <Github className="h-4 w-4" />
              <span className="hidden sm:inline">GitHub</span>
            </ExternalLink>
            <Link href="/login" className="inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90">
              Sign in <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-8 md:py-12">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">{TAGLINE}</h1>
          <p className="mt-2 text-sm text-muted-foreground">{SUBTITLE}</p>
        </div>

        <div role="tablist" aria-label="Demo videos" className="mb-4 flex flex-wrap justify-center gap-2">
          {VIDEOS.map((v) => (
            <button
              key={v.id}
              role="tab"
              aria-selected={v.id === active}
              onClick={() => setActive(v.id)}
              className={cn(
                'rounded-full border px-3.5 py-1.5 text-xs transition-colors',
                v.id === active ? 'border-primary bg-primary/10 font-medium text-primary' : 'text-muted-foreground hover:bg-accent hover:text-foreground',
              )}
            >
              {v.label} <span className="opacity-70">· {v.length}</span>
            </button>
          ))}
        </div>

        <div className="overflow-hidden rounded-lg border bg-black shadow-sm">
          {/* key remounts the element so switching tabs loads the new source */}
          <video key={video.src} className="aspect-video w-full" controls playsInline preload="metadata" poster="/demo/thumbnail.png">
            <source src={video.src} type="video/mp4" />
            Your browser cannot play this video. <a href={video.src}>Download it</a> instead.
          </video>
        </div>
        <p className="mx-auto mt-4 max-w-3xl text-center text-sm text-muted-foreground">{video.description}</p>

        <div className="mt-10 flex flex-col items-center gap-4 rounded-lg border bg-surface p-6 text-center">
          <p className="text-sm">Try it yourself: create a free account and browse a real scan in the read-only demo organization.</p>
          <Link href="/login" className="inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90">
            Create an account <ArrowRight className="h-4 w-4" />
          </Link>
          <ProjectLinksRow />
        </div>
      </main>
    </div>
  )
}
