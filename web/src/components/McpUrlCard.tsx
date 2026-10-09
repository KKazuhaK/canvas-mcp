import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Skeleton from '@mui/material/Skeleton'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { useProviders } from '@/query/hooks'
import CopyField from './CopyField'

/** The connector URL, taken from the public GET /providers response. */
export default function McpUrlCard() {
  const { t } = useTranslation()
  const providers = useProviders()
  return (
    <Card component="section" aria-labelledby="mcp-url-title">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography id="mcp-url-title" variant="h3" component="h2">
          {t('common:mcp.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('common:mcp.body')}
        </Typography>
        {providers.data ? (
          <CopyField
            value={providers.data.mcp_url}
            label={t('common:mcp.title')}
            copyLabel={t('common:mcp.copyLabel')}
          />
        ) : providers.isPending ? (
          <Skeleton variant="rounded" height={40} />
        ) : null}
      </CardContent>
    </Card>
  )
}
