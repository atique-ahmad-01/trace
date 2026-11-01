'use client'

import { useEffect, useState } from 'react'
import { Monitor, Moon, Sun } from 'lucide-react'
import { DEFAULT_THEME, THEMES, type Theme, applyTheme, saveTheme, storedTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

const META: Record<Theme, { label: string; icon: typeof Sun }> = {
  dark: { label: 'Dark', icon: Moon },
  light: { label: 'Light', icon: Sun },
  system: { label: 'System', icon: Monitor },
}

/** One button that cycles Light → Dark → System. */
export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useState<Theme | null>(null)

  useEffect(() => setTheme(storedTheme()), [])

  // In "system" mode, follow the OS when it switches between light and dark.
  useEffect(() => {
    if (theme !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => applyTheme('system')
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [theme])

  const current = theme ?? DEFAULT_THEME
  const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length]
  const Icon = META[current].icon

  return (
    <button
      type="button"
      onClick={() => {
        saveTheme(next)
        setTheme(next)
      }}
      title={`Theme: ${META[current].label}. Switch to ${META[next].label}`}
      aria-label={`Theme: ${META[current].label}. Switch to ${META[next].label}`}
      className={cn('inline-flex h-9 w-9 items-center justify-center rounded-md border text-muted-foreground hover:bg-accent hover:text-foreground', className)}
    >
      {/* Rendered only after mount: the server cannot know the stored theme. */}
      {theme && <Icon className="h-4 w-4" />}
    </button>
  )
}
