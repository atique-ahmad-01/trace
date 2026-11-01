'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Check, Copy, Github, Minus, Play, ShieldCheck } from 'lucide-react'
import { AcronymTags, Headline, Logo, Wordmark } from '@/components/brand'
import { ExternalLink, LOCAL_SETUP_URL, REPO_URL } from '@/components/project-links'
import { ThemeToggle } from '@/components/theme-toggle'
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

// A real scan of OWASP Juice Shop (an intentionally vulnerable app) at commit 717f5ef, run on a laptop with TRACE.
const SCANNERS = [
  { name: 'trivy', result: '89 findings', note: 'IaC + misconfig' },
  { name: 'semgrep', result: '139 findings', note: 'TS · JS · Python · Bash · Solidity' },
  { name: 'gitleaks', result: '69 findings', note: 'secrets' },
  { name: 'osv-scanner', result: '0 findings*', note: 'dependencies' },
]

const STEPS = [
  { title: 'Connect', body: 'A GitHub repo, any public git URL, or a local fixture. Pick a branch.' },
  { title: 'Scan', body: 'Trivy, OSV-Scanner, Semgrep and Gitleaks on an isolated snapshot. Repository code is never executed.' },
  { title: 'Enrich', body: 'Findings are deduplicated and matched against NVD, OSV, GitHub advisories and CISA KEV.' },
  { title: 'Investigate', body: 'LangGraph agents read the code through MCP tools and explain each finding with cited evidence.' },
  { title: 'Approve & verify', body: 'You approve or reject the fix. TRACE re-scans a patched snapshot, then opens a PR. It never merges.' },
]

const FINDS = [
  { title: 'Code vulnerabilities', body: 'SQL injection, command injection, unsafe deserialization and more, across about 30 languages including C and C++.', example: 'routes/login.ts:34 · SQL injection' },
  { title: 'Vulnerable dependencies', body: 'Known CVEs in Python, JavaScript, Java, Go, Ruby, Rust, PHP and .NET packages, with the fixed version.', example: 'pyyaml 5.3 → 5.4 · CVE-2020-14343' },
  { title: 'Leaked secrets', body: 'API keys, tokens and private keys committed to the repo. Values are redacted and never stored.', example: '63 secrets in Juice Shop' },
  { title: 'Infrastructure', body: 'Terraform, Dockerfiles and CI workflows: open security groups, plain HTTP, shell injection in GitHub Actions.', example: 'networking.tf:86 · open egress' },
  { title: 'AI and agent apps', body: 'Prompt-injection and tool-misuse checks, plus live probes judged with a random canary.', example: 'leakage · forbidden tool calls' },
]

const COMPARE: [string, string, string][] = [
  ['What you get', 'Hundreds of raw alerts, duplicated across tools', 'One deduplicated list, ranked by risk'],
  ['Context', 'A rule id and a line number', 'CVE intel plus an AI investigation that cites its sources'],
  ['Priority', 'Each tool’s own severity', 'A deterministic risk score from CVSS, KEV and reachability'],
  ['The fix', 'Yours to write and test', 'A proposed patch, your approval, verified by re-scan, opened as a PR'],
  ['Blind spots', 'A skipped scanner looks the same as a clean result', 'Code no scanner read never gets a passing score'],
]

const FAQ = [
  { q: 'Does TRACE change my code?', a: 'Not without you. Every fix needs a human approval, is verified on an isolated copy of the repo, and is opened as a pull request. Nothing is ever merged automatically.' },
  { q: 'Does my code leave my machine?', a: 'TRACE is self-hosted. With Ollama, scans and AI investigations run entirely on your hardware. Repository code is never sent to a hosted model unless you switch that on.' },
  { q: 'Which AI models does it use?', a: 'Any local model through Ollama, any OpenAI-compatible endpoint (vLLM, OpenAI and others), or Anthropic. You choose per organization in Settings.' },
  { q: 'Is it free?', a: 'Yes. TRACE is open source under the MIT license.' },
  {
    q: 'What can’t it do yet?',
    a: 'It does not find deep logic bugs, such as protocol state errors, that no scanner rule describes. Dependency scanning needs a lockfile, and TRACE does not yet warn you when one is missing. Small local models are slow on a CPU and tend to give guidance rather than a patch, and an AI investigation can still agree with a false positive, so review its verdict. TRACE is alpha software.',
  },
]

const QUICKSTART = `git clone ${REPO_URL}.git && cd trace
scripts/dev-setup.sh   # scanners, Python venv, npm install, .env
scripts/dev.sh         # API :8000 + console :3000`

function SectionTitle({ eyebrow, title, children }: { eyebrow: string; title: string; children?: React.ReactNode }) {
  return (
    <div className="mx-auto mb-8 max-w-2xl text-center">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">{eyebrow}</p>
      <h2 className="mt-2 text-2xl font-semibold tracking-tight md:text-3xl">{title}</h2>
      {children && <p className="mt-3 text-sm text-muted-foreground md:text-base">{children}</p>}
    </div>
  )
}

function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked: the text stays selectable */
    }
  }
  return (
    <div className="relative overflow-hidden rounded-lg border bg-elevated text-left">
      <button onClick={copy} aria-label="Copy commands" className="absolute right-2 top-2 rounded-md border bg-surface p-1.5 text-muted-foreground hover:text-foreground">
        {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
      <pre className="overflow-x-auto p-4 pr-12 font-mono text-xs leading-relaxed md:text-sm">{text}</pre>
    </div>
  )
}

function ScanPanel() {
  return (
    <div className="overflow-hidden rounded-xl border bg-surface text-left shadow-xl shadow-primary/5">
      <div className="flex items-center justify-between border-b bg-elevated px-4 py-2.5">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-sev-critical/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-sev-medium/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-success/70" />
        </div>
        <span className="font-mono text-[11px] text-muted-foreground">juice-shop · 717f5ef</span>
      </div>
      <div className="space-y-4 p-4 font-mono text-xs">
        <div className="space-y-1.5">
          {SCANNERS.map((s) => (
            <div key={s.name} className="flex items-baseline justify-between gap-3">
              <span className="text-success">✓ <span className="text-foreground">{s.name}</span></span>
              <span className="truncate text-right text-muted-foreground">
                {s.result} <span className="hidden opacity-70 sm:inline">· {s.note}</span>
              </span>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 border-t pt-3">
          <span>288 unique</span>
          <span className="text-sev-critical">20 critical</span>
          <span className="text-sev-high">101 high</span>
          <span className="text-sev-medium">40 medium</span>
        </div>
        <div className="rounded-lg border border-sev-high/40 bg-sev-high/5 p-3 font-sans">
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-semibold">SQL injection</span>
            <span className="rounded bg-sev-high/15 px-1.5 py-0.5 text-[10px] font-semibold text-sev-high">HIGH</span>
          </div>
          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">routes/login.ts:34</p>
          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
            <span className="font-medium text-foreground">AI verdict:</span> user input reaches a Sequelize query through string
            interpolation. Use parameterized queries.
          </p>
          <p className="mt-2 text-[11px] text-muted-foreground">Risk 7.0 · P2 · 6 cited sources · read via MCP</p>
        </div>
      </div>
    </div>
  )
}

export default function DemoPage() {
  const [active, setActive] = useState(VIDEOS[0].id)
  const video = VIDEOS.find((v) => v.id === active) ?? VIDEOS[0]

  return (
    <div className="min-h-screen overflow-x-hidden bg-background">
      <header className="sticky top-0 z-20 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4">
          <Link href="/demo" className="flex items-center gap-2.5">
            <Logo className="h-8 w-8" />
            <Wordmark className="text-base" />
          </Link>
          <nav className="hidden items-center gap-6 text-sm text-muted-foreground md:flex">
            <a href="#how" className="hover:text-foreground">How it works</a>
            <a href="#demo" className="hover:text-foreground">Demo</a>
            <a href="#faq" className="hover:text-foreground">FAQ</a>
            <a href="#start" className="hover:text-foreground">Quick start</a>
          </nav>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <ExternalLink href={REPO_URL} title="TRACE on GitHub" className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm text-muted-foreground hover:bg-accent hover:text-foreground">
              <Github className="h-4 w-4" />
              <span className="hidden sm:inline">GitHub</span>
            </ExternalLink>
            <Link href="/login" className="inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground hover:bg-primary/90 sm:px-4">
              Sign in <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </header>

      <main>
        {/* Hero */}
        <section className="relative">
          <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 -z-0 h-[480px] bg-[radial-gradient(ellipse_at_top,hsl(var(--primary)/0.18),transparent_60%)]" />
          <div className="relative mx-auto grid max-w-6xl items-center gap-10 px-4 pb-16 pt-12 md:pt-20 lg:grid-cols-[1.1fr_1fr]">
            <div className="text-center lg:text-left">
              <span className="inline-flex items-center gap-1.5 rounded-full border bg-surface px-3 py-1 text-xs text-muted-foreground">
                <ShieldCheck className="h-3.5 w-3.5 text-primary" /> Open source · self-hosted · MIT
              </span>
              <Headline className="mt-5 text-4xl leading-[1.1] md:text-5xl" />
              <p className="mx-auto mt-5 max-w-xl text-base text-muted-foreground md:text-lg lg:mx-0">
                TRACE runs real security scanners on your repository, lets AI agents investigate each finding with cited evidence, and
                verifies every fix by re-scanning before it opens a pull request.
              </p>
              <div className="mt-7 flex flex-wrap justify-center gap-3 lg:justify-start">
                <a href="#demo" className="inline-flex h-11 items-center gap-2 rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                  <Play className="h-4 w-4" /> Watch the demo
                </a>
                <ExternalLink href={REPO_URL} className="inline-flex h-11 items-center gap-2 rounded-md border bg-surface px-5 text-sm font-medium hover:bg-accent">
                  <Github className="h-4 w-4" /> Star on GitHub
                </ExternalLink>
              </div>
              <AcronymTags className="mt-8 justify-center lg:justify-start" />
            </div>
            <div>
              <ScanPanel />
              <p className="mt-3 text-center text-xs text-muted-foreground">
                A real TRACE scan of <ExternalLink href="https://github.com/juice-shop/juice-shop" className="underline hover:text-foreground">OWASP Juice Shop</ExternalLink>, summarized.
                <span className="mt-1 block text-[11px] opacity-80">* Juice Shop ships without a lockfile, so there were no dependency versions to check. TRACE does not flag this yet.</span>
              </p>
            </div>
          </div>
        </section>

        {/* How it works */}
        <section id="how" className="scroll-mt-16 border-t bg-surface/40 py-16">
          <div className="mx-auto max-w-6xl px-4">
            <SectionTitle eyebrow="How it works" title="From raw alert to verified fix">
              Five steps, each recorded in the audit trail.
            </SectionTitle>
            <ol className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
              {STEPS.map((s, i) => (
                <li key={s.title} className="relative rounded-lg border bg-surface p-5">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/15 text-sm font-semibold text-primary">{i + 1}</span>
                  <h3 className="mt-3 font-semibold">{s.title}</h3>
                  <p className="mt-1.5 text-sm text-muted-foreground">{s.body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* Demo videos */}
        <section id="demo" className="scroll-mt-16 border-t py-16">
          <div className="mx-auto max-w-5xl px-4">
            <SectionTitle eyebrow="Demo" title="See the whole flow in two minutes">
              Every screen and number in the video comes from a real run.
            </SectionTitle>
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
          </div>
        </section>

        {/* What it finds */}
        <section className="border-t bg-surface/40 py-16">
          <div className="mx-auto max-w-6xl px-4">
            <SectionTitle eyebrow="Coverage" title="What TRACE finds" />
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {FINDS.map((f) => (
                <div key={f.title} className="flex flex-col rounded-lg border bg-surface p-5">
                  <h3 className="font-semibold">{f.title}</h3>
                  <p className="mt-1.5 flex-1 text-sm text-muted-foreground">{f.body}</p>
                  <p className="mt-4 truncate rounded-md bg-elevated px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground">{f.example}</p>
                </div>
              ))}
              <div className="flex flex-col justify-center rounded-lg border border-dashed p-5 text-sm text-muted-foreground">
                <p>
                  <span className="font-medium text-foreground">Honest by design.</span> A scanner that cannot run is reported as unavailable or skipped,
                  never shown as a clean result.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Comparison */}
        <section className="border-t py-16">
          <div className="mx-auto max-w-5xl px-4">
            <SectionTitle eyebrow="Why TRACE" title="Scanners alone vs TRACE">
              TRACE uses the same open-source scanners you already trust. It adds what happens after the alert.
            </SectionTitle>
            <div className="overflow-hidden rounded-lg border">
              <div className="hidden grid-cols-[1fr_1.4fr_1.4fr] bg-elevated text-xs font-semibold uppercase tracking-wider text-muted-foreground sm:grid">
                <div className="p-3" />
                <div className="p-3">Scanners alone</div>
                <div className="p-3 text-primary">With TRACE</div>
              </div>
              {COMPARE.map(([label, before, after]) => (
                <div key={label} className="grid gap-2 border-t p-4 text-sm sm:grid-cols-[1fr_1.4fr_1.4fr] sm:gap-0 sm:p-0">
                  <div className="font-medium sm:p-3">{label}</div>
                  <div className="flex gap-2 text-muted-foreground sm:p-3">
                    <Minus className="mt-0.5 h-4 w-4 shrink-0 opacity-60" /> {before}
                  </div>
                  <div className="flex gap-2 sm:bg-primary/5 sm:p-3">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-primary" /> {after}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* FAQ */}
        <section id="faq" className="scroll-mt-16 border-t bg-surface/40 py-16">
          <div className="mx-auto max-w-3xl px-4">
            <SectionTitle eyebrow="FAQ" title="Questions, answered plainly" />
            <div className="space-y-3">
              {FAQ.map((f) => (
                <details key={f.q} className="group rounded-lg border bg-surface p-4 open:shadow-sm">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-medium">
                    {f.q}
                    <span className="text-muted-foreground transition-transform group-open:rotate-45">+</span>
                  </summary>
                  <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{f.a}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        {/* Quick start */}
        <section id="start" className="scroll-mt-16 border-t py-16">
          <div className="mx-auto max-w-3xl px-4 text-center">
            <SectionTitle eyebrow="Quick start" title="Run it on your machine">
              Needs Node 20+, git and Ollama. Docker Compose works too.
            </SectionTitle>
            <CopyBlock text={QUICKSTART} />
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <ExternalLink href={REPO_URL} className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                <Github className="h-4 w-4" /> Star on GitHub
              </ExternalLink>
              <ExternalLink href={LOCAL_SETUP_URL} className="inline-flex h-10 items-center gap-2 rounded-md border bg-surface px-5 text-sm font-medium hover:bg-accent">
                Read the setup guide
              </ExternalLink>
              <Link href="/login" className="inline-flex h-10 items-center gap-2 rounded-md border bg-surface px-5 text-sm font-medium hover:bg-accent">
                Try the hosted demo <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 py-6 text-xs text-muted-foreground sm:flex-row">
          <div className="flex items-center gap-2">
            <Logo className="h-5 w-5" />
            <span>
              TRACE · MIT license · built by{' '}
              <ExternalLink href="https://github.com/atique-ahmad-01" className="hover:text-foreground">Atique Ahmad</ExternalLink>
            </span>
          </div>
          <div className="flex gap-4">
            <ExternalLink href={REPO_URL} className="hover:text-foreground">GitHub</ExternalLink>
            <ExternalLink href={LOCAL_SETUP_URL} className="hover:text-foreground">Docs</ExternalLink>
            <ExternalLink href={`${REPO_URL}/blob/main/SECURITY.md`} className="hover:text-foreground">Security</ExternalLink>
          </div>
        </div>
      </footer>
    </div>
  )
}
