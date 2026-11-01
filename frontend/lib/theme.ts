export type Theme = 'dark' | 'light' | 'system'

export const THEME_KEY = 'trace.theme'
export const DEFAULT_THEME: Theme = 'light'
export const THEMES: Theme[] = ['light', 'dark', 'system']

/**
 * Runs inline in <head> before first paint so the page never flashes the wrong theme.
 * Keep in sync with applyTheme below; it cannot import anything.
 */
export const THEME_BOOT_SCRIPT = `(function(){try{var t=localStorage.getItem('${THEME_KEY}')||'${DEFAULT_THEME}';var d=t==='dark'||(t==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);document.documentElement.style.colorScheme=d?'dark':'light'}catch(e){document.documentElement.classList.remove('dark')}})()`

export function storedTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY) as Theme | null
    return t && THEMES.includes(t) ? t : DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

export function applyTheme(theme: Theme) {
  const dark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.toggle('dark', dark)
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
}

export function saveTheme(theme: Theme) {
  try {
    localStorage.setItem(THEME_KEY, theme)
  } catch {
    /* storage blocked: the choice lasts for this page view */
  }
  applyTheme(theme)
}
