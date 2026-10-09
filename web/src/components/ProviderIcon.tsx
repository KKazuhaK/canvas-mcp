import SvgIcon, { type SvgIconProps } from '@mui/material/SvgIcon'

// Inline SVG only: no remote icons, no icon fonts. Only Microsoft is offered today;
// a provider the app does not know yet gets the generic key icon.
export default function ProviderIcon({
  icon,
  ...props
}: { icon: string } & SvgIconProps) {
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
