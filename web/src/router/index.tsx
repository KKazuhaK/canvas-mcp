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
import RequireAuth from './RequireAuth'
import RequireOwner from './RequireOwner'

/** The SPA is served under /account; locations inside the router are relative to it. */
export const ROUTER_BASENAME = '/account'

export const routes: RouteObject[] = [
  {
    errorElement: <RouteError />,
    children: [
      {
        element: <PublicLayout />,
        children: [
          { path: 'login', element: <LoginView /> },
          { path: 'consent/:txn', element: <ConsentView /> },
        ],
      },
      // `/` chooses its own frame: signed-out landing or the account page.
      { index: true, element: <HomeView /> },
      {
        element: <RequireAuth />,
        children: [
          { path: 'token', element: <TokenView /> },
          { path: 'write-tools', element: <WriteToolsView /> },
          { path: 'identities', element: <IdentitiesView /> },
          { path: 'connected-apps', element: <ConnectedAppsView /> },
          { path: 'activity', element: <ActivityView /> },
          {
            element: <RequireOwner />,
            children: [
              {
                path: 'admin',
                element: <AdminLayout />,
                children: [
                  { index: true, element: <AdminAccountsView /> },
                  { path: 'enrollments', element: <AdminEnrollmentsView /> },
                  { path: 'audit', element: <AdminAuditView /> },
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
