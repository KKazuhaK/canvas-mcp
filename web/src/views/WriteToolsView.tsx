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
import type { WriteTool, WriteToolsResponse } from '@/api/types'
import ConfirmDialog from '@/components/ConfirmDialog'
import ErrorNotice from '@/components/ErrorNotice'
import PageHeader from '@/components/PageHeader'
import { useSaveWriteTools, useTurnOffWriteTools, useWriteTools } from '@/query/hooks'
import { useToast } from '@/stores/toast'
import { PageSkeleton } from './StateViews'

function enabledSet(data: WriteToolsResponse): Set<string> {
  return new Set(
    data.groups.flatMap((group) => group.tools.filter((tool) => tool.enabled).map((tool) => tool.name)),
  )
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
        <Typography variant="body2" color="text.secondary">
          {t('account:writeTools.freshNote')}
        </Typography>
      </CardContent>
    </Card>
  )
}

function ToolRow({
  tool,
  groupId,
  checked,
  disabled,
  onToggle,
}: {
  tool: WriteTool
  groupId: string
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
        opacity: tool.offered ? 1 : 0.7,
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
            color={tool.effect === 'local_write' ? 'warning' : 'default'}
            label={t(`account:writeTools.effect.${tool.effect}`)}
          />
          {groupId === 'inbox' ? (
            <Chip size="small" color="warning" label={t('account:writeTools.sendsAsYou')} />
          ) : null}
          {!tool.offered ? (
            <Chip
              size="small"
              label={tool.enabled ? t('account:writeTools.keptNotOffered') : t('account:writeTools.notAllowed')}
            />
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
  const turnOff = useTurnOffWriteTools()
  const [selected, setSelected] = useState<Set<string> | null>(null)
  const [confirmOff, setConfirmOff] = useState(false)

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
  const busy = save.isPending || turnOff.isPending
  const anyOn = enabledSet(data).size > 0

  function toggle(name: string, next: boolean) {
    setSelected((prev) => {
      const copy = new Set(prev ?? [])
      if (next) copy.add(name)
      else copy.delete(name)
      return copy
    })
  }

  function onSave() {
    // Only tools the server offers are sent; a tool that is on but no longer offered
    // stays as it is (the server keeps it), and "Turn all off" is how it goes away.
    const offered = new Set(
      data.groups.flatMap((group) => group.tools.filter((tool) => tool.offered).map((tool) => tool.name)),
    )
    const names = [...current].filter((name) => offered.has(name)).sort()
    turnOff.reset()
    save.mutate(names, {
      onSuccess: ({ result }) =>
        useToast
          .getState()
          .show(t(result === 'saved' ? 'account:writeTools.saved' : 'account:writeTools.unchanged')),
    })
  }

  return (
    <>
      <PageHeader title={t('account:writeTools.title')} subtitle={t('account:writeTools.intro')} />
      <Box sx={{ display: 'grid', gap: 2 }}>
        {!data.offered_any ? (
          <Alert severity="warning" role="note">
            {t('account:writeTools.serverDisabled')}
          </Alert>
        ) : null}
        <LayerExplainer />

        {data.groups.map((group) => {
          if (group.tools.length === 0) return null
          return (
            <Card key={group.id} component="section" aria-labelledby={`group-${group.id}`}>
              <CardContent>
                <Typography id={`group-${group.id}`} variant="h3" component="h2">
                  {t(`account:writeTools.groups.${group.id}.title`)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(`account:writeTools.groups.${group.id}.body`)}
                </Typography>
                <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, mt: 1 }}>
                  {group.tools.map((tool) => (
                    <ToolRow
                      key={tool.name}
                      tool={tool}
                      groupId={group.id}
                      checked={current.has(tool.name)}
                      disabled={!data.editable || !tool.offered || busy}
                      onToggle={(next) => toggle(tool.name, next)}
                    />
                  ))}
                </Box>
              </CardContent>
            </Card>
          )
        })}

        {data.kept_not_offered.length > 0 ? (
          <Typography variant="body2" color="text.secondary">
            {t('account:writeTools.keptList')}{' '}
            {data.kept_not_offered.map((name, index) => (
              <span key={name}>
                {index > 0 ? ', ' : ''}
                <code>{name}</code>
              </span>
            ))}
          </Typography>
        ) : null}

        {save.isError ? <ErrorNotice error={save.error} /> : null}
        {turnOff.isError && !confirmOff ? <ErrorNotice error={turnOff.error} /> : null}

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
          <Button variant="contained" disabled={!dirty || busy || !data.editable} onClick={onSave}>
            {save.isPending ? t('account:writeTools.saving') : t('account:writeTools.save')}
          </Button>
          {dirty ? (
            <>
              <Button
                disabled={busy}
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
          {anyOn ? (
            <Button color="error" disabled={busy} onClick={() => setConfirmOff(true)} sx={{ ml: 'auto' }}>
              {t('account:writeTools.turnAllOff')}
            </Button>
          ) : null}
        </Box>
      </Box>

      <ConfirmDialog
        open={confirmOff}
        title={t('account:writeTools.turnAllOffTitle')}
        body={t('account:writeTools.turnAllOffBody')}
        confirmLabel={t('account:writeTools.turnAllOff')}
        pending={turnOff.isPending}
        error={turnOff.error}
        onClose={() => {
          turnOff.reset()
          setConfirmOff(false)
        }}
        onConfirm={() => {
          save.reset()
          turnOff.mutate(undefined, {
            onSuccess: () => {
              setConfirmOff(false)
              useToast.getState().show(t('account:writeTools.allOff'))
            },
          })
        }}
      />
    </>
  )
}
