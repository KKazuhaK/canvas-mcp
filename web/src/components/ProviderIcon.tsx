import SvgIcon, { type SvgIconProps } from '@mui/material/SvgIcon'
import type { ProviderIcon as ProviderIconName } from '@/api/types'

// Inline SVG only: no remote icons, no icon fonts.
export default function ProviderIcon({
  icon,
  ...props
}: { icon: ProviderIconName } & SvgIconProps) {
  switch (icon) {
    case 'microsoft':
      return (
        <SvgIcon viewBox="0 0 24 24" aria-hidden {...props}>
          <rect x="2" y="2" width="9.5" height="9.5" fill="#f25022" />
          <rect x="12.5" y="2" width="9.5" height="9.5" fill="#7fba00" />
          <rect x="2" y="12.5" width="9.5" height="9.5" fill="#00a4ef" />
          <rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#ffb900" />
        </SvgIcon>
      )
    case 'google':
      return (
        <SvgIcon viewBox="0 0 24 24" aria-hidden {...props}>
          <path
            fill="#4285f4"
            d="M21.6 12.23c0-.68-.06-1.33-.17-1.96H12v3.7h5.4a4.62 4.62 0 0 1-2 3.03v2.52h3.24c1.9-1.75 2.96-4.32 2.96-7.29z"
          />
          <path
            fill="#34a853"
            d="M12 22c2.7 0 4.97-.9 6.63-2.43l-3.24-2.52c-.9.6-2.04.96-3.39.96-2.6 0-4.8-1.76-5.59-4.12H3.07v2.6A10 10 0 0 0 12 22z"
          />
          <path
            fill="#fbbc05"
            d="M6.41 13.89a6 6 0 0 1 0-3.78v-2.6H3.07a10 10 0 0 0 0 8.98l3.34-2.6z"
          />
          <path
            fill="#ea4335"
            d="M12 5.98c1.47 0 2.79.5 3.83 1.5l2.87-2.87C16.96 2.99 14.7 2 12 2a10 10 0 0 0-8.93 5.51l3.34 2.6C7.2 7.74 9.4 5.98 12 5.98z"
          />
        </SvgIcon>
      )
    case 'github':
      return (
        <SvgIcon viewBox="0 0 24 24" aria-hidden {...props}>
          <path
            fill="currentColor"
            d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.15-1.11-1.46-1.11-1.46-.9-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2z"
          />
        </SvgIcon>
      )
    default:
      return (
        <SvgIcon viewBox="0 0 24 24" aria-hidden {...props}>
          <path
            fill="currentColor"
            d="M12.65 10A6 6 0 1 0 11 14.6l1.4 1.4H14v2h2v2h3v-3.17l-6.35-6.83zM7 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"
          />
        </SvgIcon>
      )
  }
}
