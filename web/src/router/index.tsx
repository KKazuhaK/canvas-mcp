import { createBrowserRouter, createMemoryRouter, type RouteObject } from 'react-router'
import AdminLayout from '@/layouts/AdminLayout'
import PublicLayout from '@/layouts/PublicLayout'
import ActivityView from '@/views/ActivityView'
import ConnectedAppsView from '@/views/ConnectedAppsView'
import ConsentView from '@/views/ConsentView'
import HomeView from '@/views/HomeView'
import IdentitiesView from '@/views/IdentitiesView'
import LoginView from '@/views/LoginView'
import { NotFoundView, RouteError } from '@/views/StateViews'
import TokenView from '@/views/TokenView'
import WriteToolsView from '@/views/WriteToolsView'
import AdminAccountsView from '@/views/admin/AdminAccountsView'
import AdminAuditView from '@/views/admin/AdminAuditView'
import AdminEnrollmentsView from '@/views/admin/AdminEnrollmentsView'
import DocumentTitle from './DocumentTitle'
import RequireAuth from './RequireAuth'
import RequireOwner from './RequireOwner'

/** The SPA is served under /account; locations inside the router are relative to it. */
export const ROUTER_BASENAME = '/account'

export const routes: RouteObject[] = [
  {
    element: <DocumentTitle />,
    errorElement: <RouteError />,
    children: [
      {
        element: <PublicLayout />,
        children: [
          { path: 'login', element: <LoginView />, handle: { titleKey: 'common:actions.signIn' } },
          { path: 'consent/:txn', element: <ConsentView /> },
        ],
      },
      // `/` chooses its own frame: signed-out landing or the account page.
      { index: true, element: <HomeView /> },
      {
        element: <RequireAuth />,
        children: [
          { path: 'token', element: <TokenView />, handle: { titleKey: 'common:nav.token' } },
          { path: 'write-tools', element: <WriteToolsView />, handle: { titleKey: 'common:nav.writeTools' } },
          { path: 'identities', element: <IdentitiesView />, handle: { titleKey: 'common:nav.identities' } },
          { path: 'connected-apps', element: <ConnectedAppsView />, handle: { titleKey: 'common:nav.connectedApps' } },
          { path: 'activity', element: <ActivityView />, handle: { titleKey: 'common:nav.activity' } },
          {
            element: <RequireOwner />,
            children: [
              {
                path: 'admin',
                element: <AdminLayout />,
                children: [
                  { index: true, element: <AdminAccountsView />, handle: { titleKey: 'admin:accounts.title' } },
                  { path: 'enrollments', element: <AdminEnrollmentsView />, handle: { titleKey: 'admin:enrollments.title' } },
                  { path: 'audit', element: <AdminAuditView />, handle: { titleKey: 'admin:audit.title' } },
                ],
              },
            ],
          },
        ],
      },
      { path: '*', element: <NotFoundView /> },
    ],
  },
]

export function createAppRouter() {
  return createBrowserRouter(routes, { basename: ROUTER_BASENAME })
}

/** For tests: same route table, in-memory history, no basename. */
export function createTestRouter(initialEntries: string[]) {
  return createMemoryRouter(routes, { initialEntries })
}
