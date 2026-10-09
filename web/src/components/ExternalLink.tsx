import Link, { type LinkProps } from '@mui/material/Link'
import { safeHttpsUrl } from '@/utils/returnTo'

/**
 * The only way the app renders an outbound link. https only; anything else
 * (javascript:, data:, http:, garbage) renders as plain text, so a hostile
 * client_uri cannot become a clickable payload.
 */
export default function ExternalLink({
  href,
  children,
  ...props
}: { href: string | null | undefined } & Omit<LinkProps, 'href' | 'target' | 'rel'>) {
  const safe = safeHttpsUrl(href)
  if (safe === null) return <span>{children}</span>
  return (
    <Link href={safe} target="_blank" rel="noopener noreferrer" {...props}>
      {children}
    </Link>
  )
}
