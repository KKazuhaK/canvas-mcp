import Box from '@mui/material/Box'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import { Outlet, useLocation } from 'react-router'
import { Link as RouterLink } from 'react-router'
import { useTranslation } from 'react-i18next'

const TABS = [
  { to: '/admin', labelKey: 'common:nav.adminAccounts' },
  { to: '/admin/enrollments', labelKey: 'common:nav.adminEnrollments' },
  { to: '/admin/audit', labelKey: 'common:nav.adminAudit' },
]

/** Tab strip shared by the three owner-only admin pages. */
export default function AdminLayout() {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  // The router basename is stripped, so pathname is '/admin', '/admin/audit', ...
  const current = TABS.find((tab) => tab.to === pathname.replace(/\/$/, ''))?.to ?? false
  return (
    <Box>
      <Tabs
        value={current}
        variant="scrollable"
        scrollButtons="auto"
        aria-label={t('common:nav.admin')}
        sx={{ mb: 3, borderBottom: 1, borderColor: 'divider' }}
      >
        {TABS.map((tab) => (
          <Tab
            key={tab.to}
            value={tab.to}
            label={t(tab.labelKey)}
            component={RouterLink}
            to={tab.to}
          />
        ))}
      </Tabs>
      <Outlet />
    </Box>
  )
}
