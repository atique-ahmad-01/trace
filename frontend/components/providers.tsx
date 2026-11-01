'use client'

import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { usePathname, useRouter } from 'next/navigation'
import { createContext, useContext, useEffect, useState } from 'react'
import { api, session } from '@/lib/api'

type Me = { user: { id: string; email: string; username: string; full_name?: string }; organizations: { id: string; name: string; slug: string; role: string }[] }

const AuthContext = createContext<{ me: Me | null; orgId: string | null; role: string | null; logout: () => void }>({ me: null, orgId: null, role: null, logout: () => {} })

export const useAuth = () => useContext(AuthContext)

function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const isPublic = pathname.startsWith('/login') || pathname.startsWith('/verify-email') || pathname.startsWith('/demo')
  const [ready, setReady] = useState(false)
  useEffect(() => {
    if (!isPublic && !session.token()) router.replace('/login')
    setReady(true)
  }, [isPublic, router])

  const { data: me } = useQuery<Me>({ queryKey: ['me'], queryFn: () => api.get('/auth/me'), enabled: ready && !isPublic && !!session.token(), staleTime: 5 * 60_000 })
  const orgId = me ? session.org() && me.organizations.some((o) => o.id === session.org()) ? session.org() : me.organizations[0]?.id ?? null : null
  useEffect(() => {
    if (orgId && orgId !== session.org()) session.setOrg(orgId)
  }, [orgId])
  const role = me?.organizations.find((o) => o.id === orgId)?.role ?? null
  const logout = () => {
    session.setToken(null)
    session.setOrg(null)
    window.location.href = '/login'
  }
  if (!ready) return null
  return <AuthContext.Provider value={{ me: me ?? null, orgId, role, logout }}>{children}</AuthContext.Provider>
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { staleTime: 15_000, refetchOnWindowFocus: false, retry: (count, err: any) => count < 2 && !(err?.status >= 400 && err?.status < 500) },
        },
      }),
  )
  return (
    <QueryClientProvider client={queryClient}>
      <AuthGate>{children}</AuthGate>
    </QueryClientProvider>
  )
}
