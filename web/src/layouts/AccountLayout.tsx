import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings'
import HistoryIcon from '@mui/icons-material/History'
import HomeIcon from '@mui/icons-material/Home'
import KeyIcon from '@mui/icons-material/Key'
import LogoutIcon from '@mui/icons-material/Logout'
import MenuIcon from '@mui/icons-material/Menu'
import TuneIcon from '@mui/icons-material/Tune'
import AppBar from '@mui/material/AppBar'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Container from '@mui/material/Container'
import Divider from '@mui/material/Divider'
import Drawer from '@mui/material/Drawer'
import IconButton from '@mui/material/IconButton'
import List from '@mui/material/List'
import ListItemButton from '@mui/material/ListItemButton'
import ListItemIcon from '@mui/material/ListItemIcon'
import ListItemText from '@mui/material/ListItemText'
import Toolbar from '@mui/material/Toolbar'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useState, type ElementType, type ReactNode } from 'react'
import { NavLink, Link as RouterLink, Outlet } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { Features, MeResponse } from '@/api/types'
import LanguageToggle from '@/components/LanguageToggle'
import ThemeToggle from '@/components/ThemeToggle'
import { useLogout } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { errorText } from '@/utils/errorText'

const DRAWER_WIDTH = 248

interface NavItem {
  to: string
  labelKey: string
  Icon: ElementType
  end?: boolean
}

/** The nav the server's feature flags allow: a screen it does not serve is not listed. */
function navFor(features: Features): NavItem[] {
  return [
    { to: '/', labelKey: 'common:nav.home', Icon: HomeIcon, end: true },
    { to: '/token', labelKey: 'common:nav.token', Icon: KeyIcon },
    ...(features.write_tools
      ? [{ to: '/write-tools', labelKey: 'common:nav.writeTools', Icon: TuneIcon }]
      : []),
    { to: '/activity', labelKey: 'common:nav.activity', Icon: HistoryIcon },
    ...(features.admin
      ? [{ to: '/admin', labelKey: 'common:nav.admin', Icon: AdminPanelSettingsIcon }]
      : []),
  ]
}

/**
 * Signed-in shell: top bar, left nav on md+, a drawer below that. Rendered
 * around `children` when given, else around the matched child route.
 */
export default function AccountLayout({ me, children }: { me: MeResponse; children?: ReactNode }) {
  const { t } = useTranslation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const logout = useLogout()
  const isOwner = me.features.admin
  const active = me.account.status === 'active'

  function signOut() {
    logout.mutate(undefined, {
      onError: (error) => useToast.getState().show(errorText(t, error), 'error'),
    })
  }

  const items = navFor(me.features)

  const nav = (
    <Box component="nav" aria-label={t('common:nav.main')} sx={{ pt: 1 }}>
      <List>
        {items.map(({ to, labelKey, Icon, end }) => (
          <ListItemButton
            key={to}
            component={NavLink}
            to={to}
            end={end}
            onClick={() => setMobileOpen(false)}
            sx={{ '&.active': { bgcolor: 'action.selected', fontWeight: 600 } }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>
              <Icon fontSize="small" />
            </ListItemIcon>
            <ListItemText primary={t(labelKey)} />
          </ListItemButton>
        ))}
      </List>
    </Box>
  )

  const displayName = me.account.display_name

  return (
    <Box sx={{ minHeight: '100dvh', display: 'flex', flexDirection: 'column' }}>
      <Box
        component="a"
        href="#main"
        sx={{
          position: 'absolute',
          left: -9999,
          '&:focus': { left: 8, top: 8, zIndex: 2000, bgcolor: 'background.paper', p: 1 },
        }}
      >
        {t('common:chrome.skipToContent')}
      </Box>
      <AppBar
        position="sticky"
        color="inherit"
        elevation={0}
        sx={{ borderBottom: 1, borderColor: 'divider', zIndex: (theme) => theme.zIndex.drawer + 1 }}
      >
        <Toolbar sx={{ gap: 1, px: { xs: 1, sm: 2 } }}>
          {active ? (
            <IconButton
              edge="start"
              aria-label={t('common:actions.openMenu')}
              onClick={() => setMobileOpen(true)}
              sx={{ display: { md: 'none' } }}
            >
              <MenuIcon />
            </IconButton>
          ) : null}
          <Typography
            component={RouterLink}
            to="/"
            variant="h3"
            sx={{ color: 'text.primary', textDecoration: 'none', flexShrink: 0 }}
          >
            {t('common:brand')}
          </Typography>
          <Box sx={{ flex: 1 }} />
          <Tooltip title={me.account.username || displayName}>
            <Typography
              variant="body2"
              noWrap
              sx={{ maxWidth: { xs: 90, sm: 180 }, color: 'text.secondary' }}
            >
              {displayName}
            </Typography>
          </Tooltip>
          {isOwner && active ? (
            <Button
              component={RouterLink}
              to="/admin"
              color="inherit"
              size="small"
              sx={{ display: { xs: 'none', sm: 'inline-flex' } }}
            >
              {t('common:nav.admin')}
            </Button>
          ) : null}
          <LanguageToggle />
          <ThemeToggle />
          <Button
            color="inherit"
            size="small"
            onClick={signOut}
            disabled={logout.isPending}
            startIcon={<LogoutIcon fontSize="small" />}
            aria-label={t('common:actions.signOut')}
            sx={{ '& .MuiButton-startIcon': { mr: { xs: 0, sm: 0.5 } }, minWidth: 0 }}
          >
            <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
              {t('common:actions.signOut')}
            </Box>
          </Button>
        </Toolbar>
      </AppBar>

      <Box sx={{ display: 'flex', flex: 1, minWidth: 0 }}>
        {active ? (
          <>
            <Drawer
              variant="temporary"
              open={mobileOpen}
              onClose={() => setMobileOpen(false)}
              ModalProps={{ keepMounted: false }}
              sx={{
                display: { xs: 'block', md: 'none' },
                '& .MuiDrawer-paper': { width: DRAWER_WIDTH },
              }}
            >
              <Toolbar />
              <Typography variant="body2" color="text.secondary" noWrap sx={{ px: 2, pt: 1 }}>
                {t('common:chrome.signedInAs', { name: displayName })}
              </Typography>
              <Divider sx={{ mt: 1 }} />
              {nav}
            </Drawer>
            <Box
              sx={{
                display: { xs: 'none', md: 'block' },
                width: DRAWER_WIDTH,
                flexShrink: 0,
                borderRight: 1,
                borderColor: 'divider',
              }}
            >
              {nav}
            </Box>
          </>
        ) : null}
        <Container
          component="main"
          id="main"
          maxWidth="md"
          sx={{ flex: 1, minWidth: 0, py: 3, px: 2 }}
        >
          {children ?? <Outlet />}
        </Container>
      </Box>
    </Box>
  )
}
