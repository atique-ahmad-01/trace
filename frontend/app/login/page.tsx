'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { AcronymList, AcronymTags, Logo, SUBTITLE, TAGLINE, Wordmark } from '@/components/brand'
import { Button, ErrorState, Input, Label } from '@/components/ui'
import { API_URL, api, login, session } from '@/lib/api'

const IS_LOCAL_API = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(API_URL)

type ServerState = 'checking' | 'waking' | 'ready' | 'down'

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
  const server = useServerWarmup()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      if (mode === 'register') {
        const res = await api.post<{ demo_organization_id?: string | null }>('/auth/register', { email, password, username, organization_name: org || undefined })
        // Land new visitors on the populated demo organization; their own org is one switch away.
        session.setOrg(res.demo_organization_id ?? null)
      }
      await login(email, password)
      router.replace('/')
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid min-h-screen bg-background lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden overflow-hidden border-r bg-surface lg:flex lg:flex-col lg:justify-center lg:px-16">
        <div
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{ background: 'radial-gradient(600px circle at 15% 20%, hsl(186 85% 50% / 0.12), transparent 60%), radial-gradient(500px circle at 85% 85%, hsl(258 90% 66% / 0.12), transparent 60%)' }}
          aria-hidden
        />
        <div className="relative max-w-md">
          <div className="mb-8 flex items-center gap-3">
            <Logo className="h-12 w-12" />
            <Wordmark className="text-3xl" />
          </div>
          <h2 className="text-3xl font-semibold leading-tight tracking-tight">{TAGLINE}</h2>
          <p className="mt-3 text-sm text-muted-foreground">{SUBTITLE}</p>
          <AcronymList className="mt-10" />
        </div>
      </section>
      <div className="flex items-center justify-center px-4 py-10">
        <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <Logo className="mb-3 h-14 w-14" />
          <h1><Wordmark className="text-2xl" /></h1>
          <p className="mt-2 text-sm font-medium">{TAGLINE}</p>
          <p className="mt-1 text-xs text-muted-foreground">{SUBTITLE}</p>
          <AcronymTags className="mt-4 justify-center lg:hidden" />
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-lg border bg-surface p-6 shadow-sm">
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
          {error ? <ErrorState error={error} /> : null}
          <Button type="submit" className="w-full" loading={loading}>
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            {mode === 'login' ? 'No account? ' : 'Have an account? '}
            <button type="button" className="text-primary hover:underline" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
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
