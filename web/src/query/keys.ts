import type { AdminEnrollmentFilter, AdminStatusFilter } from '@/api/types'

// Query keys never contain secrets: no Canvas token, no CSRF token, no session
// material, and no search text typed into a secret field.
export const keys = {
  providers: ['providers'] as const,
  me: ['me'] as const,
  schools: ['schools'] as const,
  writeTools: ['write-tools'] as const,
  loginHistory: ['login-history'] as const,
  // The consent request id is a one-time secret of this browser: it is never part of a key.
  consent: ['consent'] as const,
  grants: ['grants'] as const,
  adminGrants: (accountId: string) => ['admin', 'grants', accountId] as const,
  admin: ['admin'] as const,
  adminAccounts: (status: AdminStatusFilter | '') => ['admin', 'accounts', status] as const,
  adminEnrollments: (filter: AdminEnrollmentFilter) => ['admin', 'enrollments', filter] as const,
  adminAudit: ['admin', 'audit'] as const,
}
