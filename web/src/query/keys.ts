import type { AdminAccountFilters, AdminAuditFilters } from '@/api/endpoints'

// Query keys never contain secrets: no Canvas token, no CSRF token, no session
// material. A consent transaction id is an opaque, short-lived handle.
export const keys = {
  providers: ['providers'] as const,
  me: ['me'] as const,
  canvasToken: ['canvas-token'] as const,
  writeTools: ['write-tools'] as const,
  identities: ['identities'] as const,
  grants: ['grants'] as const,
  loginHistory: ['login-history'] as const,
  consent: (txn: string) => ['consent', txn] as const,
  adminAccounts: (filters: AdminAccountFilters) => ['admin', 'accounts', filters] as const,
  adminEnrollments: ['admin', 'enrollments'] as const,
  adminAudit: (filters: AdminAuditFilters) => ['admin', 'audit', filters] as const,
}
