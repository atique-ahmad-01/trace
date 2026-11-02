'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, Play } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { ACRONYM, Logo, Wordmark } from '@/components/brand'
import { DoodleField, HighlightBar } from '@/components/marketing'
import { ThemeToggle } from '@/components/theme-toggle'
import { Button, ErrorState, Input, Label, Notice } from '@/components/ui'
import { API_URL, ApiError, api, login, session } from '@/lib/api'

const IS_LOCAL_API = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(API_URL)

type ServerState = 'checking' | 'waking' | 'ready' | 'down'

const PANEL_DOODLES = [
  { kind: 'shield', top: '6%', left: '6%' }, { kind: 'bug', top: '82%', left: '8%', size: 46 }, { kind: 'search', top: '10%', left: '84%', size: 48 },
  { kind: 'lock', top: '86%', left: '80%', size: 44 }, { kind: 'doc', top: '46%', left: '90%', size: 42 },
] as const

const FORM_DOODLES = [
  { kind: 'doc', top: '12%', left: '8%', size: 44 }, { kind: 'check', top: '80%', left: '10%', size: 46 }, { kind: 'warn', top: '16%', left: '84%', size: 40 },
  { kind: 'code', top: '78%', left: '82%', size: 44 },
] as const

/** Pings /health as soon as the page opens, so a sleeping backend boots while the visitor types. */
function useServerWarmup(): ServerState {
  const [state, setState] = useState<ServerState>('checking')
  useEffect(() => {
    let cancelled = false
    const slow = setTimeout(() => !cancelled && setState((s) => (s === 'checking' ? 'waking' : s)), 1500)
    const started = Date.now()
    async function ping() {
      while (!cancelled && Date.now() - started < 180_000) {
        try {
          const res = await fetch(`${API_URL}/health`, { cache: 'no-store', signal: AbortSignal.timeout(65_000) })
          if (res.ok) {
            if (!cancelled) setState('ready')
            return
          }
        } catch {
          /* still booting: retry */
        }
        await new Promise((r) => setTimeout(r, 3000))
      }
      if (!cancelled) setState('down')
    }
    ping()
    return () => {
      cancelled = true
      clearTimeout(slow)
    }
  }, [])
  return state
}

export default function LoginPage() {
  const router = useRouter()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [username, setUsername] = useState('')
  const [org, setOrg] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(false)
  // Shown after sign-up, after resending a link, or when the verify page sends the visitor back here.
  const [notice, setNotice] = useState<{ text: string; link?: string } | null>(null)
  const [unverified, setUnverified] = useState(false)
  const [resending, setResending] = useState(false)
  const server = useServerWarmup()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('verified') === '1') setNotice({ text: 'Email verified. You can sign in now.' })
    const e = params.get('email')
    if (e) setEmail(e)
  }, [])

  function switchMode(next: 'login' | 'register') {
    setMode(next)
    setError(null)
    setNotice(null)
    setUnverified(false)
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setNotice(null)
    setUnverified(false)
    setLoading(true)
    try {
      if (mode === 'register') {
        const res = await api.post<{ demo_organization_id?: string | null; verification_required?: boolean; verification_url?: string }>(
          '/auth/register',
          { email, password, username, organization_name: org || undefined },
        )
        // Land new visitors on the populated demo organization once they sign in; their own org is one switch away.
        session.setOrg(res.demo_organization_id ?? null)
        // Registration never signs in: the visitor confirms their email, then signs in here.
        setMode('login')
        setPassword('')
        setNotice(
          res.verification_required
            ? { text: `Account created. We sent a verification link to ${email}. Open it, then sign in.`, link: res.verification_url }
            : { text: 'Account created. Sign in to continue.' },
        )
        return
      }
      await login(email, password)
      router.replace('/overview')
    } catch (err) {
      if (err instanceof ApiError && (err.detail as any)?.code === 'email_not_verified') setUnverified(true)
      setError(err)
    } finally {
      setLoading(false)
    }
  }

  async function resend() {
    setResending(true)
    try {
      const res = await api.post<{ message: string; verification_url?: string }>('/auth/resend-verification', { email })
      setError(null)
      setUnverified(false)
      setNotice({ text: res.message, link: res.verification_url })
    } catch (err) {
      setError(err)
    } finally {
      setResending(false)
    }
  }

  return (
    <div className="grid min-h-screen bg-m-paper text-m-ink lg:grid-cols-[1.1fr_1fr]">
      <section className="m-grid relative hidden overflow-hidden border-r-[3px] border-m-ink bg-m-deep text-[#fbfdfc] lg:flex lg:flex-col lg:justify-center lg:px-14 xl:px-20">
        <DoodleField spots={[...PANEL_DOODLES]} className="text-m-teal/30" />
        <div className="relative max-w-xl">
          <Link href="/" className="mb-10 flex w-fit items-center gap-3" title="Back to the TRACE website">
            <Logo className="h-12 w-12" />
            <span className="m-display -skew-x-6 text-4xl italic text-m-teal">TRACE</span>
          </Link>
          <span className="inline-flex items-center gap-1.5 rounded-full border-2 border-m-teal/60 px-3 py-1 font-mono text-xs font-semibold text-[#cfe9e3]">
            <span className="h-2 w-2 rounded-full bg-m-teal" /> open source · self-hosted · MIT
          </span>
          <h2 className="m-display mt-6 text-5xl xl:text-6xl">Find real vulnerabilities.</h2>
          <p className="m-display mt-4 text-3xl xl:text-4xl">
            <HighlightBar className="py-0.5">Fix them only with your approval.</HighlightBar>
          </p>
          <p className="mt-7 max-w-md text-sm leading-relaxed text-[#a9c9c2]">
            Real scanners, AI investigations with cited evidence, and fixes verified by re-scanning before any pull request.
          </p>
          <ul className="mt-8 grid grid-cols-5 gap-2">
            {ACRONYM.map((a) => (
              <li key={a.letter} title={a.detail} className="rounded-xl border-2 border-m-teal/40 bg-[#123632] px-2 py-3 text-center">
                <span className="m-display block text-3xl text-m-teal">{a.letter}</span>
                <span className="mt-1 block font-mono text-[10px] text-[#a9c9c2]">{a.word}</span>
              </li>
            ))}
          </ul>
          <Link href="/#demo" className="group mt-8 flex items-center gap-4 rounded-2xl border-2 border-m-teal/50 bg-[#123632] p-3 transition-colors hover:border-m-teal">
            <span className="relative block w-40 shrink-0 overflow-hidden rounded-lg border-2 border-[#05110f]">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src="/demo/thumbnail.png" alt="" className="block aspect-video w-full object-cover" />
              <span className="absolute inset-0 flex items-center justify-center bg-black/25">
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-m-teal text-[#0b1f1d] transition-transform group-hover:scale-110">
                  <Play className="h-4 w-4 fill-current" />
                </span>
              </span>
            </span>
            <span>
              <span className="m-display block text-xl">Watch the 90-second demo</span>
              <span className="mt-0.5 block text-xs text-[#a9c9c2]">Scan, investigation, approved fix, verified.</span>
            </span>
          </Link>
        </div>
      </section>
      <div className="relative flex items-center justify-center overflow-hidden px-4 py-16">
        <DoodleField spots={[...FORM_DOODLES]} className="text-m-ink/10" />
        <Link href="/" className="absolute left-4 top-4 z-10 inline-flex items-center gap-1.5 font-display text-sm font-bold text-m-ink/70 hover:text-m-ink">
          <ArrowLeft className="h-4 w-4" /> Back to website
        </Link>
        <ThemeToggle className="absolute right-4 top-3 z-10 border-2 border-m-ink text-m-ink" />
        <div className="relative w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <Logo className="mb-3 h-14 w-14 lg:hidden" />
          <p className="lg:hidden"><Wordmark className="text-2xl" /></p>
          <p className="m-display mt-3 text-lg lg:hidden">
            Find real vulnerabilities. <span className="text-m-tealdeep">Fix them only with your approval.</span>
          </p>
          <h1 className="m-display mt-6 text-4xl lg:mt-0">{mode === 'login' ? 'Sign in.' : 'Create your account.'}</h1>
          <p className="mt-2 text-sm text-m-muted">
            {mode === 'login' ? 'Welcome back. Your scans are waiting.' : 'Free and open source. Takes a minute.'}
          </p>
        </div>
        <form onSubmit={submit} className="m-card space-y-4 p-6 [&_input]:h-11 [&_input]:rounded-xl [&_input]:border-2 [&_input]:border-m-ink/70 [&_input]:bg-m-paper [&_input]:text-m-ink [&_input]:focus-visible:border-m-ink [&_input]:focus-visible:ring-m-teal [&_label]:font-mono [&_label]:font-bold [&_label]:uppercase [&_label]:tracking-wider [&_label]:text-m-muted">
          <div>
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          {mode === 'register' && (
            <>
              <div>
                <Label htmlFor="username">Username</Label>
                <Input id="username" required minLength={3} pattern="[A-Za-z0-9_.\-]+" value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div>
                <Label htmlFor="org" hint="optional">Organization name</Label>
                <Input id="org" value={org} onChange={(e) => setOrg(e.target.value)} />
              </div>
            </>
          )}
          <div>
            <Label htmlFor="password" hint={mode === 'register' ? 'min 10 characters' : undefined}>Password</Label>
            <Input id="password" type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required minLength={mode === 'register' ? 10 : 1} value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {notice && (
            <Notice tone="success">
              {notice.text}
              {notice.link && (
                <span className="mt-1 block text-[11px]">
                  Email delivery is not configured on this server.{' '}
                  <a href={notice.link} className="text-primary underline">Open verification link</a>
                </span>
              )}
            </Notice>
          )}
          {error ? <ErrorState error={error} /> : null}
          {unverified && (
            <Button type="button" variant="outline" className="w-full" loading={resending} onClick={resend}>
              Resend verification email
            </Button>
          )}
          <Button type="submit" className="m-btn h-12 w-full bg-m-teal text-[#0b1f1d] hover:bg-m-teal" loading={loading}>
            {mode === 'login' ? 'Sign in' : 'Create account'} {!loading && <ArrowRight className="h-4 w-4" />}
          </Button>
          <p className="text-center text-sm text-m-muted">
            {mode === 'login' ? 'No account? ' : 'Have an account? '}
            <button type="button" className="font-display font-extrabold text-m-tealdeep hover:underline" onClick={() => switchMode(mode === 'login' ? 'register' : 'login')}>
              {mode === 'login' ? 'Register' : 'Sign in'}
            </button>
          </p>
        </form>
        {server !== 'ready' && (
          <p role="status" className="mt-4 flex items-center justify-center gap-2 text-center text-xs text-muted-foreground">
            {server === 'down' ? (
              <span className="text-destructive">Server is not responding. Please try again in a few minutes.</span>
            ) : (
              <>
                <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" aria-hidden />
                {server === 'waking' ? 'Waking the server, this can take up to a minute…' : 'Connecting to server…'}
              </>
            )}
          </p>
        )}
        {mode === 'register' && !IS_LOCAL_API && (
          <p className="mt-4 text-center text-[11px] text-muted-foreground">New accounts get read-only access to the TRACE Demo organization with real scan results.</p>
        )}
        {IS_LOCAL_API && <p className="mt-4 text-center text-[11px] text-muted-foreground">Local demo admin: admin@trace.example (password from DEMO_ADMIN_PASSWORD)</p>}
        </div>
      </div>
    </div>
  )
}
