import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import { useTranslation } from 'react-i18next'

interface Paging {
  hasNextPage: boolean
  isFetchingNextPage: boolean
  fetchNextPage: () => Promise<unknown>
}

export default function LoadMore({ query }: { query: Paging }) {
  const { t } = useTranslation()
  if (!query.hasNextPage) return null
  return (
    <Box sx={{ mt: 2 }}>
      <Button disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>
        {query.isFetchingNextPage ? t('common:states.loading') : t('common:actions.loadMore')}
      </Button>
    </Box>
  )
}
