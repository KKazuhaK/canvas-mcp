import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CloseRounded from '@mui/icons-material/CloseRounded'
import Drawer from '@mui/material/Drawer'
import Typography from '@mui/material/Typography'
import { useId, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

export default function DetailDrawer({ title, open, onClose, children }: { title: string; open: boolean; onClose: () => void; children: ReactNode }) {
  const { t } = useTranslation()
  const id = useId()
  return <Drawer anchor="right" open={open} onClose={onClose} sx={{ zIndex: (theme) => theme.zIndex.modal }}
    slotProps={{ paper: { role: 'dialog', 'aria-modal': true, 'aria-labelledby': id, sx: { width: { xs: '100%', sm: 660 }, maxWidth: '100%' } } }}>
    <Box sx={{ position: 'sticky', top: 0, bgcolor: 'background.paper', zIndex: 1, p: 2, borderBottom: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: 2 }}>
      <Typography id={id} component="h2" variant="h2" sx={{ overflowWrap: 'anywhere' }}>{title}</Typography>
      <Button size="small" color="inherit" startIcon={<CloseRounded />} onClick={onClose} sx={{ flexShrink: 0 }}>{t('common:actions.close')}</Button>
    </Box>
    <Box sx={{ p: { xs: 2, sm: 3 }, display: 'grid', gap: 3 }}>{children}</Box>
  </Drawer>
}
