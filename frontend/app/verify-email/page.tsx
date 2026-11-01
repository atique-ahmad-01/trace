'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Logo, Wordmark } from '@/components/brand'
import { Button, ErrorState } from '@/components/ui'
import { api } from '@/lib/api'

type State = { kind: 'verifying' } | { kind: 'done'; email: string } | { kind: 'error'; error: unknown }

export default function VerifyEmailPage() {
  const router = useRouter()
  const [state, setState] = useState<State>({ kind: 'verifying' })
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return // StrictMode runs effects twice in development
    started.current = true
    const token = new URLSearchParams(window.location.search).get('token')
    if (!token) {
      setState({ kind: 'error', error: new Error('This verification link is incomplete. Open the link from your email again.') })
      return
    }
    api
      .post<{ email: string }>('/auth/verify-email', { token })
      .then((res) => {
        setState({ kind: 'done', email: res.email })
        setTimeout(() => router.replace(`/login?verified=1&email=${encodeURIComponent(res.email)}`), 2500)
      })
      .catch((error) => setState({ kind: 'error', error }))
  }, [router])

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm text-center">
        <Logo className="mx-auto mb-3 h-14 w-14" />
        <h1 className="mb-6"><Wordmark className="text-2xl" /></h1>
        <div className="space-y-4 rounded-lg border bg-surface p-6 text-sm shadow-sm">
          {state.kind === 'verifying' && <p className="text-muted-foreground">Verifying your email…</p>}
          {state.kind === 'done' && (
            <>
              <p className="font-medium">Email verified</p>
              <p className="text-muted-foreground">{state.email} is confirmed. Taking you to sign in…</p>
            </>
          )}
          {state.kind === 'error' && <ErrorState error={state.error} className="text-left" />}
          {state.kind !== 'verifying' && (
            <Link href={state.kind === 'done' ? `/login?verified=1&email=${encodeURIComponent(state.email)}` : '/login'}>
              <Button className="mt-2 w-full">Go to sign in</Button>
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}
