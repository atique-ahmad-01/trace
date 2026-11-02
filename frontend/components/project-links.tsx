/** TRACE is open source: links to the code and the local setup guide (used by the public landing page). */
export const REPO_URL = 'https://github.com/atique-ahmad-01/trace'
export const LOCAL_SETUP_URL = `${REPO_URL}#-quick-start`

export function ExternalLink({ href, className, title, children }: { href: string; className?: string; title?: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" title={title} className={className}>
      {children}
    </a>
  )
}
