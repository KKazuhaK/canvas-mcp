import { createBrowserRouter, createMemoryRouter, type RouteObject } from 'react-router'
import AdminLayout from '@/layouts/AdminLayout'
import PublicLayout from '@/layouts/PublicLayout'
import ActivityView from '@/views/ActivityView'
import ConnectedAppsView from '@/views/ConnectedAppsView'
import ConsentView from '@/views/ConsentView'
import HomeView from '@/views/HomeView'
import SignInView from '@/views/SignInView'
import { NotFoundView, RouteError } from '@/views/StateViews'
import TokenView from '@/views/TokenView'
import WriteToolsView from '@/views/WriteToolsView'
import AdminAccountsView from '@/views/admin/AdminAccountsView'
import AdminAuditView from '@/views/admin/AdminAuditView'
import AdminEnrollmentsView from '@/views/admin/AdminEnrollmentsView'
import DocumentTitle from './DocumentTitle'
import RequireAuth from './RequireAuth'
import RequireFeature from './RequireFeature'
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
          // The server-side sign-in lives at /account/login and /account/callback (not
          // routes of this app); this page is where a failed sign-in comes back to.
          { path: 'sign-in', element: <SignInView />, handle: { titleKey: 'common:actions.signIn' } },
        ],
      },
      // `/` chooses its own frame: signed-out landing or the account page.
      { index: true, element: <HomeView /> },
      // An app asks to be connected (the server's own authorization server). Outside RequireAuth on
      // purpose: a signed-out visitor is sent to the sign-in of this very request, not to /sign-in.
      { path: 'consent', element: <ConsentView />, handle: { titleKey: 'account:consent.title' } },
      {
        element: <RequireAuth />,
        children: [
          { path: 'token', element: <TokenView />, handle: { titleKey: 'common:nav.token' } },
          {
            element: <RequireFeature feature="write_tools" />,
            children: [
              { path: 'write-tools', element: <WriteToolsView />, handle: { titleKey: 'common:nav.writeTools' } },
            ],
          },
          {
            element: <RequireFeature feature="connected_apps" />,
            children: [
              {
                path: 'connected-apps',
                element: <ConnectedAppsView />,
                handle: { titleKey: 'common:nav.connectedApps' },
              },
            ],
          },
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
