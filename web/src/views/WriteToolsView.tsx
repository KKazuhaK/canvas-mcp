import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Chip from '@mui/material/Chip'
import Switch from '@mui/material/Switch'
import Typography from '@mui/material/Typography'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { RiskLevel, WriteTool, WriteToolGroup, WriteToolsResponse } from '@/api/types'
import ErrorNotice from '@/components/ErrorNotice'
import PageHeader from '@/components/PageHeader'
import { useSaveWriteTools, useWriteTools } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { PageSkeleton } from './StateViews'

const GROUP_ORDER: WriteToolGroup[] = ['planner_calendar', 'submissions', 'modules', 'messages']
const RISK_COLOR: Record<RiskLevel, 'success' | 'warning' | 'error'> = {
  low: 'success',
  medium: 'warning',
  high: 'error',
}

function enabledSet(data: WriteToolsResponse): Set<string> {
  return new Set(data.tools.filter((tool) => tool.enabled).map((tool) => tool.name))
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  return a.size === b.size && [...a].every((x) => b.has(x))
}

function LayerExplainer() {
  const { t } = useTranslation()
  const steps = [
    t('account:writeTools.layers.server'),
    t('account:writeTools.layers.you'),
    `${t('account:writeTools.layers.course')} (${t('account:writeTools.layers.courseNote')})`,
  ]
  return (
    <Card component="section" aria-labelledby="layers-title">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography id="layers-title" variant="h3" component="h2">
          {t('account:writeTools.layers.title')}
        </Typography>
        <Box
          component="ol"
          sx={{ listStyle: 'none', m: 0, p: 0, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 0.5 }}
        >
          {steps.map((label, index) => (
            <Box component="li" key={label} sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5 }}>
              <Chip label={label} size="small" variant={index === 2 ? 'outlined' : 'filled'} />
              {index < steps.length - 1 ? <ChevronRightIcon fontSize="small" aria-hidden /> : null}
            </Box>
          ))}
        </Box>
        <Typography variant="body2" color="text.secondary">
          {t('account:writeTools.layersNote')}
        </Typography>
      </CardContent>
    </Card>
  )
}

function ToolRow({
  tool,
  checked,
  disabled,
  onToggle,
}: {
  tool: WriteTool
  checked: boolean
  disabled: boolean
  onToggle: (next: boolean) => void
}) {
  const { t } = useTranslation()
  const labelId = `tool-${tool.name}-label`
  const label = t(`account:writeTools.tools.${tool.name}.label`, { defaultValue: tool.name })
  const description = t(`account:writeTools.tools.${tool.name}.description`, {
    defaultValue: t('account:writeTools.unknownTool'),
  })
  return (
    <Box
      component="li"
      sx={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: 2,
        py: 1.5,
        opacity: tool.server_allowed ? 1 : 0.7,
      }}
    >
      <Box sx={{ minWidth: 0 }}>
        <Typography id={labelId} sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>
          {label}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {description}
        </Typography>
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.75 }}>
          <Chip
            size="small"
            variant="outlined"
            color={RISK_COLOR[tool.risk]}
            label={t(`account:writeTools.risk.${tool.risk}`)}
          />
          {tool.group === 'messages' ? (
            <Chip size="small" color="warning" label={t('account:writeTools.sendsAsYou')} />
          ) : null}
          {!tool.server_allowed ? (
            <Chip size="small" label={t('account:writeTools.notAllowed')} />
          ) : null}
        </Box>
      </Box>
      <Switch
        checked={checked}
        disabled={disabled}
        onChange={(_e, next) => onToggle(next)}
        slotProps={{ input: { 'aria-labelledby': labelId } }}
      />
    </Box>
  )
}

/** /write-tools: which state-changing tools Claude may use as you. */
export default function WriteToolsView() {
  const { t } = useTranslation()
  const query = useWriteTools()
  const save = useSaveWriteTools()
  const [selected, setSelected] = useState<Set<string> | null>(null)

  // Seed (and re-seed after a save) from the server's answer.
  useEffect(() => {
    if (query.data) setSelected(enabledSet(query.data))
  }, [query.data])

  const dirty = useMemo(
    () => (query.data && selected ? !sameSet(selected, enabledSet(query.data)) : false),
    [query.data, selected],
  )

  // Dirty-state guard: warn before the tab is closed or reloaded with unsaved changes.
  useEffect(() => {
    if (!dirty) return
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault()
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [dirty])

  if (query.isPending || (query.data && !selected)) {
    return (
      <>
        <PageHeader title={t('account:writeTools.title')} />
        <PageSkeleton />
      </>
    )
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title={t('account:writeTools.title')} />
        <ErrorNotice error={query.error} onRetry={() => void query.refetch()} />
      </>
    )
  }

  const data = query.data
  const current = selected as Set<string>
  const locked = !data.server_enabled

  function toggle(name: string, next: boolean) {
    setSelected((prev) => {
      const copy = new Set(prev ?? [])
      if (next) copy.add(name)
      else copy.delete(name)
      return copy
    })
  }

  function onSave() {
    // Only names the server allows are sent; the server rejects the rest anyway.
    const allowed = new Set(data.tools.filter((tool) => tool.server_allowed).map((tool) => tool.name))
    const names = [...current].filter((name) => allowed.has(name)).sort()
    save.mutate(names, {
      onSuccess: () => useToast.getState().show(t('account:writeTools.saved')),
    })
  }

  return (
    <>
      <PageHeader title={t('account:writeTools.title')} subtitle={t('account:writeTools.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {locked ? <Alert severity="warning" role="note">{t('account:writeTools.serverDisabled')}</Alert> : null}
        <LayerExplainer />

        {GROUP_ORDER.map((group) => {
          const tools = data.tools.filter((tool) => tool.group === group)
          if (tools.length === 0) return null
          return (
            <Card key={group} component="section" aria-labelledby={`group-${group}`}>
              <CardContent>
                <Typography id={`group-${group}`} variant="h3" component="h2">
                  {t(`account:writeTools.groups.${group}.title`)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(`account:writeTools.groups.${group}.body`)}
                </Typography>
                <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, mt: 1 }}>
                  {tools.map((tool) => (
                    <ToolRow
                      key={tool.name}
                      tool={tool}
                      checked={current.has(tool.name)}
                      disabled={locked || !tool.server_allowed || save.isPending}
                      onToggle={(next) => toggle(tool.name, next)}
                    />
                  ))}
                </Box>
              </CardContent>
            </Card>
          )
        })}

        {save.isError ? <ErrorNotice error={save.error} /> : null}

        <Box
          sx={{
            position: 'sticky',
            bottom: 0,
            display: 'flex',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 1.5,
            py: 1.5,
            bgcolor: 'background.default',
          }}
        >
          <Button
            variant="contained"
            disabled={!dirty || save.isPending || locked}
            onClick={onSave}
          >
            {save.isPending ? t('account:writeTools.saving') : t('account:writeTools.save')}
          </Button>
          {dirty ? (
            <>
              <Button
                disabled={save.isPending}
                onClick={() => {
                  save.reset()
                  setSelected(enabledSet(data))
                }}
              >
                {t('account:writeTools.discard')}
              </Button>
              <Typography variant="body2" color="text.secondary" role="status">
                {t('account:writeTools.unsaved')}
              </Typography>
            </>
          ) : null}
        </Box>
      </Box>
    </>
  )
}
