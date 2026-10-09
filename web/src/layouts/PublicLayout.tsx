import Box from '@mui/material/Box'
import Container from '@mui/material/Container'
import Typography from '@mui/material/Typography'
import type { ReactNode } from 'react'
import { Link as RouterLink, Outlet } from 'react-router'
import { useTranslation } from 'react-i18next'
import LanguageToggle from '@/components/LanguageToggle'
import ThemeToggle from '@/components/ThemeToggle'

/** Centered-card shell for signed-out and hand-off screens. Used as a layout route or wrapper. */
export default function PublicLayout({
  children,
  width = 'sm',
}: {
  children?: ReactNode
  width?: 'xs' | 'sm' | 'md'
}) {
  const { t } = useTranslation()
  return (
    <Box sx={{ minHeight: '100dvh', display: 'flex', flexDirection: 'column' }}>
      <Box
        component="header"
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1,
        }}
      >
        <Typography
          component={RouterLink}
          to="/"
          variant="h3"
          sx={{ color: 'text.primary', textDecoration: 'none' }}
        >
          {t('common:brand')}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <LanguageToggle />
          <ThemeToggle />
        </Box>
      </Box>
      <Container
        component="main"
        id="main"
        maxWidth={width}
        sx={{ flex: 1, display: 'grid', alignContent: 'start', gap: 2, py: 3, px: 2 }}
      >
        {children ?? <Outlet />}
      </Container>
    </Box>
  )
}
