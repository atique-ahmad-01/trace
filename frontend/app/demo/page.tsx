'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Check, Copy, Github, Play, Plus, X } from 'lucide-react'
import { ACRONYM, Logo, Wordmark } from '@/components/brand'
import { BrowserFrame, Doodle, DoodleField, HighlightBar, Pill, Reveal, SectionHeading, Terminal, type DoodleKind } from '@/components/marketing'
import { ExternalLink, LOCAL_SETUP_URL, REPO_URL } from '@/components/project-links'
import { ThemeToggle } from '@/components/theme-toggle'
import { session } from '@/lib/api'
import { cn } from '@/lib/utils'

const VIDEO = {
  src: '/demo/trace-demo.mp4',
  description:
    'A 90-second narrated tour: four scanners merged into one deduplicated list, live vulnerability intelligence, a real AI investigation with cited evidence, a deterministic risk score, and a human-approved fix verified by re-scanning.',
}

// A real scan of OWASP Juice Shop (an intentionally vulnerable app) at commit 717f5ef, run on a laptop with TRACE.
const SCANNERS = [
  { name: 'trivy', result: '89 findings', note: 'IaC + misconfig' },
  { name: 'semgrep', result: '139 findings', note: 'TS · JS · Python · Bash · Solidity' },
  { name: 'gitleaks', result: '69 findings', note: 'secrets' },
  { name: 'osv-scanner', result: '0 findings*', note: 'dependencies' },
]

const STATS = [
  { value: '297 → 288', label: 'raw findings from that scan, deduplicated into one list' },
  { value: '4', label: 'open-source scanners, side by side' },
  { value: '4', label: 'intel sources: NVD, OSV, GitHub Advisories, CISA KEV' },
  { value: '0', label: 'automatic merges. Every fix waits for you.' },
]

const MARQUEE = ['Trivy', 'OSV-Scanner', 'Semgrep', 'Gitleaks', 'NVD', 'OSV', 'GitHub Advisories', 'CISA KEV', 'LangGraph agents', 'MCP tools', 'Ollama', 're-scan verified', 'human approval', 'audit trail']

const STEPS = [
  { title: 'Connect', body: 'A GitHub repo, any public git URL, or a local fixture. Pick a branch.' },
  { title: 'Scan', body: 'Trivy, OSV-Scanner, Semgrep and Gitleaks on an isolated snapshot. Repository code is never executed.' },
  { title: 'Enrich', body: 'Findings are deduplicated and matched against NVD, OSV, GitHub advisories and CISA KEV.' },
  { title: 'Investigate', body: 'LangGraph agents read the code through MCP tools and explain each finding with cited evidence.' },
  { title: 'Approve & verify', body: 'You approve or reject the fix. TRACE re-scans a patched snapshot, then opens a PR. It never merges.' },
]

const FINDS: { title: string; body: string; example: string; icon: DoodleKind }[] = [
  { title: 'Code vulnerabilities', icon: 'code', body: 'SQL injection, command injection, unsafe deserialization and more, across about 30 languages including C and C++.', example: 'routes/login.ts:34 · SQL injection' },
  { title: 'Vulnerable dependencies', icon: 'folder', body: 'Known CVEs in Python, JavaScript, Java, Go, Ruby, Rust, PHP and .NET packages, with the fixed version.', example: 'pyyaml 5.3 → 5.4 · CVE-2020-14343' },
  { title: 'Leaked secrets', icon: 'lock', body: 'API keys, tokens and private keys committed to the repo. Values are redacted and never stored.', example: '63 secrets in Juice Shop' },
  { title: 'Infrastructure', icon: 'warn', body: 'Terraform, Dockerfiles and CI workflows: open security groups, plain HTTP, shell injection in GitHub Actions.', example: 'networking.tf:86 · open egress' },
  { title: 'AI and agent apps', icon: 'question', body: 'Prompt-injection and tool-misuse checks, plus live probes judged with a random canary.', example: 'leakage · forbidden tool calls' },
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

const HERO_DOODLES = [
  { kind: 'doc', top: '8%', left: '3%' }, { kind: 'bug', top: '72%', left: '5%', size: 46 }, { kind: 'warn', top: '12%', left: '46%', size: 40 },
  { kind: 'search', top: '84%', left: '40%', size: 44 }, { kind: 'shield', top: '6%', left: '90%' }, { kind: 'lock', top: '78%', left: '92%', size: 44 },
  { kind: 'code', top: '44%', left: '1%', size: 40 }, { kind: 'question', top: '48%', left: '95%', size: 42 },
] as const

const SPARSE_DOODLES = [
  { kind: 'doc', top: '6%', left: '4%', size: 44 }, { kind: 'bug', top: '80%', left: '7%', size: 40 }, { kind: 'shield', top: '10%', left: '92%', size: 46 },
  { kind: 'search', top: '82%', left: '90%', size: 42 },
] as const

function CopyButton({ text }: { text: string }) {
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
    <button onClick={copy} aria-label="Copy commands" className="inline-flex items-center gap-1.5 rounded-md border border-[#2a5a53] px-2 py-1 font-mono text-[11px] text-[#8fb0aa] hover:text-[#e8fff9]">
      {copied ? <Check className="h-3.5 w-3.5 text-[#2fd6b6]" /> : <Copy className="h-3.5 w-3.5" />} {copied ? 'copied' : 'copy'}
    </button>
  )
}

function ScanPanel() {
  return (
    <BrowserFrame url="localhost:3000/scans · juice-shop @ 717f5ef" tag="Real scan">
      <div className="space-y-4 p-4 font-mono text-xs text-m-ink md:p-5">
        <div className="space-y-2">
          {SCANNERS.map((s) => (
            <div key={s.name} className="flex items-baseline justify-between gap-3">
              <span>
                <span className="mr-1.5 inline-block rounded bg-m-teal px-1 font-bold text-[#0b1f1d]">✓</span>
                {s.name}
              </span>
              <span className="truncate text-right text-m-muted">
                {s.result} <span className="hidden opacity-80 sm:inline">· {s.note}</span>
              </span>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-2 border-t-2 border-dashed border-m-ink/20 pt-3">
          <span className="rounded-md bg-m-mint px-2 py-0.5 font-bold">288 unique</span>
          <span className="rounded-md bg-sev-critical/15 px-2 py-0.5 font-bold text-sev-critical">20 critical</span>
          <span className="rounded-md bg-sev-high/15 px-2 py-0.5 font-bold text-sev-high">101 high</span>
          <span className="rounded-md bg-sev-medium/15 px-2 py-0.5 font-bold text-sev-medium">40 medium</span>
        </div>
        <div className="rounded-xl border-2 border-m-ink bg-m-paper p-3 font-sans">
          <div className="flex items-center justify-between gap-2">
            <span className="font-display text-base font-extrabold">SQL injection</span>
            <span className="rounded-md bg-sev-high px-1.5 py-0.5 font-mono text-[10px] font-bold text-white">HIGH</span>
          </div>
          <p className="mt-0.5 font-mono text-[11px] text-m-muted">routes/login.ts:34</p>
          <p className="mt-2 text-xs leading-relaxed text-m-muted">
            <span className="font-semibold text-m-ink">AI verdict:</span> user input reaches a Sequelize query through string interpolation. Use
            parameterized queries.
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10px]">
            <span className="rounded bg-m-mint px-1.5 py-0.5">risk 7.0 · P2</span>
            <span className="rounded bg-m-mint px-1.5 py-0.5">6 cited sources</span>
            <span className="rounded bg-m-mint px-1.5 py-0.5">read via MCP</span>
          </div>
        </div>
      </div>
    </BrowserFrame>
  )
}

const navLink = 'font-display font-bold text-m-ink/70 transition-colors hover:text-m-ink'

export default function DemoPage() {
  // Signed-in visitors get a way back into the app; read after mount so the server render matches.
  const [signedIn, setSignedIn] = useState(false)
  useEffect(() => setSignedIn(!!session.token()), [])
  return (
    <div className="min-h-screen overflow-x-hidden bg-m-paper text-m-ink">
      <header className="sticky top-0 z-30 border-b-2 border-m-ink bg-m-paper/85 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo className="h-8 w-8" />
            <Wordmark className="text-base" />
          </Link>
          <nav className="hidden items-center gap-7 text-sm md:flex">
            <a href="#how" className={navLink}>How it works</a>
            <a href="#demo" className={navLink}>Demo</a>
            <a href="#faq" className={navLink}>FAQ</a>
            <a href="#start" className={navLink}>Quick start</a>
          </nav>
          <div className="flex items-center gap-2">
            <ThemeToggle className="border-2 border-m-ink text-m-ink" />
            <ExternalLink href={REPO_URL} title="TRACE on GitHub" className="m-btn hidden h-9 bg-m-card px-3 text-sm sm:inline-flex">
              <Github className="h-4 w-4" /> GitHub
            </ExternalLink>
            <Link href={signedIn ? '/overview' : '/login'} className="m-btn h-9 bg-m-teal px-3 text-sm text-[#0b1f1d] sm:px-4">
              {signedIn ? 'Open dashboard' : 'Sign in'} <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </header>

      <main>
        {/* Hero */}
        <section className="relative">
          <DoodleField spots={[...HERO_DOODLES]} className="text-m-ink/20" />
          <div className="relative mx-auto grid max-w-6xl grid-cols-1 items-center gap-12 px-4 pb-20 pt-14 md:pt-20 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
            <div className="min-w-0 text-center lg:text-left">
              <div className="m-rise">
                <Pill>
                  <span className="h-2 w-2 rounded-full bg-m-teal" /> open source · self-hosted · MIT
                </Pill>
              </div>
              <div className="m-rise" style={{ ['--d' as string]: '80ms' }}>
                <h1 className="m-display mt-6 text-5xl md:text-7xl">Find real vulnerabilities.</h1>
              </div>
              <div className="m-rise" style={{ ['--d' as string]: '180ms' }}>
                <p className="m-display mt-5 text-[2rem] leading-tight md:text-5xl">
                  <HighlightBar className="py-1">Fix them only with your approval.</HighlightBar>
                </p>
              </div>
              <div className="m-rise" style={{ ['--d' as string]: '260ms' }}>
                <p className="mx-auto mt-8 max-w-xl text-base text-m-muted md:text-lg lg:mx-0">
                  TRACE runs real security scanners on your repository, lets AI agents investigate each finding with cited evidence, and verifies
                  every fix by re-scanning before it opens a pull request.
                </p>
              </div>
              <div className="m-rise" style={{ ['--d' as string]: '340ms' }}>
                <div className="mt-8 flex flex-wrap justify-center gap-4 lg:justify-start">
                  <a href="#demo" className="m-btn bg-m-teal text-[#0b1f1d]">
                    <Play className="h-4 w-4 fill-current" /> Watch the 90-second demo
                  </a>
                </div>
              </div>
              <div className="m-rise" style={{ ['--d' as string]: '420ms' }}>
                <ul className="mt-9 flex flex-wrap justify-center gap-2 lg:justify-start">
                  {ACRONYM.map((a) => (
                    <li key={a.letter} title={a.detail} className="rounded-lg border-2 border-m-ink/80 bg-m-card px-2.5 py-1 font-mono text-xs">
                      <span className="font-bold text-m-tealdeep">{a.letter}</span> {a.word}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="m-rise relative" style={{ ['--d' as string]: '200ms' }}>
              <div className="relative">
                <div className="m-float relative" style={{ ['--dur' as string]: '11s', ['--dx' as string]: '0px', ['--dy' as string]: '-10px', ['--r' as string]: '1.2deg' }}>
                  <ScanPanel />
                </div>
                <div className="absolute -right-3 top-[42%] rotate-6 rounded-xl border-[3px] border-m-ink bg-m-teal px-3 py-1.5 font-display text-lg font-extrabold text-[#0b1f1d] shadow-[4px_5px_0_rgb(var(--m-shadow))] md:-right-6">
                  4/4 scanners ✓
                </div>
                <div className="absolute -bottom-6 -left-3 -rotate-3 rounded-xl border-[3px] border-m-ink bg-m-card px-3 py-1.5 font-display text-lg font-extrabold shadow-[4px_5px_0_rgb(var(--m-shadow))] md:-left-8">
                  verified by re-scan
                </div>
              </div>
              <p className="mt-10 text-center text-xs text-m-muted">
                A real TRACE scan of <ExternalLink href="https://github.com/juice-shop/juice-shop" className="underline hover:text-m-ink">OWASP Juice Shop</ExternalLink>, summarized.
                <span className="mt-1 block text-[11px] opacity-80">* Juice Shop ships without a lockfile, so there were no dependency versions to check. TRACE does not flag this yet.</span>
              </p>
            </div>
          </div>
        </section>

        {/* Stats + marquee */}
        <section className="m-grid relative border-y-2 border-m-ink bg-m-deep text-[#fbfdfc]">
          <div className="mx-auto grid max-w-6xl grid-cols-2 gap-8 px-4 py-14 md:grid-cols-4">
            {STATS.map((s, i) => (
              <Reveal key={s.label} delay={i * 90}>
                <div className="m-display text-4xl text-m-teal md:text-5xl">{s.value}</div>
                <p className="mt-2 text-sm text-[#a9c9c2]">{s.label}</p>
              </Reveal>
            ))}
          </div>
          <div className="overflow-hidden border-t border-white/10 py-4">
            <div className="m-marquee flex w-max gap-8 whitespace-nowrap font-display text-2xl font-extrabold text-white/25">
              {[...MARQUEE, ...MARQUEE].map((w, i) => (
                <span key={i} className="flex items-center gap-8">
                  {w} <span className="text-m-teal/60">✦</span>
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* Demo video */}
        <section id="demo" className="m-slashes relative scroll-mt-16 border-b-2 border-m-ink bg-m-teal py-20 text-[#0b1f1d]">
          <div className="mx-auto max-w-5xl px-4">
            <Reveal className="mx-auto mb-10 max-w-3xl text-center">
              <p className="font-mono text-xs font-bold uppercase tracking-[0.25em]">Demo</p>
              <h2 className="m-display mt-3 text-4xl md:text-6xl">See the whole flow in 90 seconds.</h2>
              <p className="mx-auto mt-4 max-w-2xl text-base md:text-lg">The product screens in the video come from a real run.</p>
            </Reveal>
            <Reveal delay={120}>
              <BrowserFrame url="trace-psi.me/#demo" tag="▶ 1:23">
                <video className="block aspect-video w-full bg-black" controls playsInline preload="metadata" poster="/demo/thumbnail.png">
                  <source src={VIDEO.src} type="video/mp4" />
                  Your browser cannot play this video. <a href={VIDEO.src}>Download it</a> instead.
                </video>
              </BrowserFrame>
            </Reveal>
            <p className="mx-auto mt-8 max-w-3xl text-center text-sm font-medium md:text-base">{VIDEO.description}</p>
          </div>
        </section>

        {/* How it works */}
        <section id="how" className="m-grid scroll-mt-16 border-b-2 border-m-ink bg-m-deep py-20 text-[#fbfdfc]">
          <div className="mx-auto max-w-6xl px-4">
            <SectionHeading dark eyebrow="How it works" title="From raw alert" accent="to verified fix.">
              Five steps, each recorded in the audit trail.
            </SectionHeading>
            <ol className="relative grid gap-5 sm:grid-cols-2 lg:grid-cols-5">
              <div aria-hidden className="absolute left-0 right-0 top-10 hidden border-t-2 border-dashed border-m-teal/40 lg:block" />
              {STEPS.map((s, i) => (
                <Reveal as="li" key={s.title} delay={i * 110} className="relative">
                  <div className="h-full rounded-2xl border-2 border-m-teal/50 bg-[#123632] p-5 transition-transform hover:-translate-y-1">
                    <span className="m-display inline-flex h-12 w-12 items-center justify-center rounded-xl bg-m-teal text-xl text-[#0b1f1d]">{String(i + 1).padStart(2, '0')}</span>
                    <h3 className="m-display mt-4 text-2xl">{s.title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-[#a9c9c2]">{s.body}</p>
                  </div>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        {/* What it finds */}
        <section className="relative border-b-2 border-m-ink py-20">
          <DoodleField spots={[...SPARSE_DOODLES]} className="text-m-ink/15" />
          <div className="relative mx-auto max-w-6xl px-4">
            <SectionHeading eyebrow="Coverage" title="What TRACE" accent="finds." />
            <div className="grid gap-7 sm:grid-cols-2 lg:grid-cols-3">
              {FINDS.map((f, i) => (
                <Reveal key={f.title} delay={(i % 3) * 100}>
                  <div className="m-card flex h-full flex-col p-6 transition-transform hover:-translate-y-1">
                    <Doodle kind={f.icon} className="h-11 w-11 text-m-tealdeep" />
                    <h3 className="m-display mt-4 text-2xl">{f.title}</h3>
                    <p className="mt-2 flex-1 text-sm leading-relaxed text-m-muted">{f.body}</p>
                    <p className="mt-5 truncate rounded-lg bg-m-mint px-3 py-2 font-mono text-[11px] font-semibold">{f.example}</p>
                  </div>
                </Reveal>
              ))}
              <Reveal delay={200}>
                <div className="flex h-full flex-col justify-center rounded-2xl border-[3px] border-dashed border-m-ink/40 p-6">
                  <p className="m-display text-2xl">Honest by design.</p>
                  <p className="mt-2 text-sm leading-relaxed text-m-muted">A scanner that cannot run is reported as unavailable or skipped, never shown as a clean result.</p>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* Comparison */}
        <section className="border-b-2 border-m-ink bg-m-mint py-20">
          <div className="mx-auto max-w-6xl px-4">
            <SectionHeading eyebrow="Why TRACE" title="Scanners alone" accent="vs TRACE.">
              TRACE uses the same open-source scanners you already trust. It adds what happens after the alert.
            </SectionHeading>
            <div className="grid gap-8 md:grid-cols-2">
              <Reveal>
                <div className="h-full rounded-2xl border-[3px] border-dashed border-m-ink/40 bg-m-paper/60 p-6">
                  <p className="m-display text-2xl text-m-muted">Scanners alone</p>
                  <ul className="mt-5 space-y-4">
                    {COMPARE.map(([label, before]) => (
                      <li key={label} className="flex gap-3">
                        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-sev-critical/15 text-sev-critical"><X className="h-4 w-4" /></span>
                        <span>
                          <span className="block font-mono text-[11px] font-bold uppercase tracking-wider text-m-muted">{label}</span>
                          <span className="text-sm text-m-muted">{before}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </Reveal>
              <Reveal delay={120}>
                <div className="m-card h-full p-6">
                  <p className="m-display text-2xl">
                    With <HighlightBar className="px-2 text-2xl">TRACE</HighlightBar>
                  </p>
                  <ul className="mt-5 space-y-4">
                    {COMPARE.map(([label, , after]) => (
                      <li key={label} className="flex gap-3">
                        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-m-teal text-[#0b1f1d]"><Check className="h-4 w-4" /></span>
                        <span>
                          <span className="block font-mono text-[11px] font-bold uppercase tracking-wider text-m-tealdeep">{label}</span>
                          <span className="text-sm font-medium">{after}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* FAQ */}
        <section id="faq" className="scroll-mt-16 border-b-2 border-m-ink py-20">
          <div className="mx-auto max-w-3xl px-4">
            <SectionHeading eyebrow="FAQ" title="Questions," accent="answered plainly." />
            <div className="space-y-5">
              {FAQ.map((f, i) => (
                <Reveal key={f.q} delay={i * 60}>
                  <details className="m-card-sm group p-5">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-display text-lg font-extrabold">
                      {f.q}
                      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border-2 border-m-ink transition-transform group-open:rotate-45 group-open:bg-m-teal">
                        <Plus className="h-4 w-4" />
                      </span>
                    </summary>
                    <p className="mt-3 text-sm leading-relaxed text-m-muted">{f.a}</p>
                  </details>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* Quick start */}
        <section id="start" className="m-grid scroll-mt-16 border-b-2 border-m-ink bg-m-deep py-20 text-[#fbfdfc]">
          <div className="mx-auto max-w-3xl px-4 text-center">
            <SectionHeading dark eyebrow="Quick start" title="Run it on" accent="your machine.">
              Needs Node 20+, git and Ollama. Docker Compose works too.
            </SectionHeading>
            <Reveal>
              <Terminal action={<CopyButton text={QUICKSTART} />}>
                <pre className="overflow-x-auto p-5 font-mono text-xs leading-relaxed text-[#e8fff9] md:text-sm">
                  {QUICKSTART.split('\n').map((line) => {
                    const [cmd, comment] = line.split('#')
                    return (
                      <div key={line}>
                        <span className="text-m-teal">$ </span>
                        {cmd}
                        {comment && <span className="text-[#6f8f89]">#{comment}</span>}
                      </div>
                    )
                  })}
                </pre>
              </Terminal>
            </Reveal>
            <div className="mt-10 flex flex-wrap justify-center gap-4">
              <ExternalLink href={REPO_URL} className="m-btn border-[#05110f] bg-m-teal text-[#0b1f1d]" >
                <Github className="h-4 w-4" /> Star on GitHub
              </ExternalLink>
              <ExternalLink href={LOCAL_SETUP_URL} className="m-btn border-[#05110f] bg-[#fbfdfc] text-[#0b1f1d]">
                Read the setup guide
              </ExternalLink>
              <Link href="/login" className="m-btn border-m-teal bg-transparent text-[#fbfdfc]">
                Try the hosted demo <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        </section>

        {/* Closing card, like the video's end card */}
        <section className="relative overflow-hidden py-24">
          <DoodleField spots={[...HERO_DOODLES]} className="text-m-ink/15" />
          <Reveal className="relative mx-auto max-w-4xl px-4 text-center">
            <div className="flex items-center justify-center gap-4">
              <Logo className="h-16 w-16 md:h-20 md:w-20" />
              <span className="m-display -skew-x-6 text-6xl italic md:text-8xl">TRACE</span>
            </div>
            <p className="m-display mt-8 text-3xl md:text-5xl">Find real vulnerabilities.</p>
            <p className="m-display mt-4 text-[1.7rem] md:text-5xl">
              <HighlightBar className="py-1">Fix them only with your approval.</HighlightBar>
            </p>
            <div className="mt-12 flex flex-wrap justify-center gap-4">
              <Link href={signedIn ? '/overview' : '/login'} className="m-btn bg-m-teal text-[#0b1f1d]">
                {signedIn ? 'Open dashboard' : 'Try the hosted demo'} <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          </Reveal>
        </section>
      </main>

      <footer className="border-t-2 border-m-ink">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-3 px-4 py-6 text-xs text-m-muted sm:flex-row">
          <div className="flex items-center gap-2">
            <Logo className="h-5 w-5" />
            <span>
              TRACE · MIT license · built by{' '}
              <ExternalLink href="https://github.com/atique-ahmad-01" className="font-semibold hover:text-m-ink">Atique Ahmad</ExternalLink>
            </span>
          </div>
          <div className="flex gap-4 font-semibold">
            <ExternalLink href={REPO_URL} className="hover:text-m-ink">GitHub</ExternalLink>
            <ExternalLink href={LOCAL_SETUP_URL} className="hover:text-m-ink">Docs</ExternalLink>
            <ExternalLink href={`${REPO_URL}/blob/main/SECURITY.md`} className={cn('hover:text-m-ink')}>Security</ExternalLink>
          </div>
        </div>
      </footer>
    </div>
  )
}
