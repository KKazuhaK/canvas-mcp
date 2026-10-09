import BrightnessAutoIcon from '@mui/icons-material/BrightnessAuto'
import DarkModeIcon from '@mui/icons-material/DarkMode'
import LightModeIcon from '@mui/icons-material/LightMode'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import { useTranslation } from 'react-i18next'
import { useThemeStore, type ThemeMode } from '@/stores/theme'

const ORDER: ThemeMode[] = ['auto', 'light', 'dark']

/** Cycles auto -> light -> dark. The choice is a per-viewer convenience. */
export default function ThemeToggle() {
  const { t } = useTranslation()
  const mode = useThemeStore((s) => s.mode)
  const setMode = useThemeStore((s) => s.setMode)
  const next = ORDER[(ORDER.indexOf(mode) + 1) % ORDER.length]
  const label = `${t('common:theme.label')}: ${t(`common:theme.${mode}`)}`
  const Icon = mode === 'dark' ? DarkModeIcon : mode === 'light' ? LightModeIcon : BrightnessAutoIcon
  return (
    <Tooltip title={label}>
      <IconButton color="inherit" size="small" aria-label={label} onClick={() => setMode(next)}>
        <Icon fontSize="small" />
      </IconButton>
    </Tooltip>
  )
}
