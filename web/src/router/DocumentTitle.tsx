import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet, useMatches } from 'react-router'

/** Route `handle` shape: the i18n key of the page's name in the tab title. */
export interface RouteHandle {
  titleKey?: string
}

function titleKeyOf(handle: unknown): string | undefined {
  if (typeof handle !== 'object' || handle === null) return undefined
  const key = (handle as RouteHandle).titleKey
  return typeof key === 'string' ? key : undefined
}

/**
 * Keeps document.title in step with the language and the matched route, so the
 * tab and screen-reader page title are localized like the rest of the UI. The
 * deepest match that names a title wins; routes without one (home, 404, errors)
 * get the plain app title.
 */
export default function DocumentTitle() {
  const { t, i18n } = useTranslation()
  const matches = useMatches()
  let key: string | undefined
  for (const match of matches) key = titleKeyOf(match.handle) ?? key

  const base = t('common:pageTitle')
  const page = key ? t(key) : ''
  const title = page && page !== base ? `${page} - ${base}` : base

  useEffect(() => {
    document.title = title
  }, [title, i18n.language])

  return <Outlet />
}
