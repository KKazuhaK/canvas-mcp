import Box from '@mui/material/Box'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router'

export const settingsTopics = ['site', 'providers', 'access', 'schools', 'mail'] as const
export type SettingsTopic = typeof settingsTopics[number]

export function useSettingsTopic(): SettingsTopic {
  const [params] = useSearchParams()
  const value = params.get('topic')
  return settingsTopics.includes(value as SettingsTopic) ? value as SettingsTopic : 'site'
}

export default function SettingsTopics() {
  const { t } = useTranslation()
  const [, setParams] = useSearchParams()
  const selected = useSettingsTopic()
  return <Box>
    <Tabs value={selected} variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile
      aria-label={t('admin:workspace.topics')} onChange={(_, value: SettingsTopic) => setParams({ topic: value })}>
      {settingsTopics.map((topic) => <Tab key={topic} value={topic} id={`settings-tab-${topic}`}
        aria-controls={`settings-panel-${topic}`} label={t(`admin:workspace.${topic}.title`)} />)}
    </Tabs>
    <Typography color="text.secondary" sx={{ mt: 2 }}>{t(`admin:workspace.${selected}.help`)}</Typography>
  </Box>
}
