import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { getVersion } from '@/api/endpoints'

/** Only active administrators may request or display the image stamp. */
export default function BuildFooter({ isAdmin }: { isAdmin: boolean }) {
  return isAdmin ? <AdminBuildFooter /> : null
}

function AdminBuildFooter() {
  const { t } = useTranslation()
  const { data } = useQuery({ queryKey: ['server-build'], queryFn: getVersion, staleTime: 60_000, retry: false })
  if (!data || typeof data.version !== 'string' || typeof data.commit !== 'string' || typeof data.built_at !== 'string') return null
  return (
    <Box component="footer" aria-label={t('common:build.label')} sx={{ px: 2, py: 1, textAlign: 'center' }}>
      <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
        {t('common:build.version')}: {data.version} · commit: <span title={data.commit}>{data.commit.slice(0, 12)}</span> · {t('common:build.built')}: {data.built_at}
      </Typography>
    </Box>
  )
}
