import { and, eq, type SQL } from 'drizzle-orm';
import { scans } from '../schema/index.js';

/**
 * G-03 authorization scope.
 *
 * A shared service must pass an AuthScope so that every scan read/write is
 * constrained to the caller's tenant. The local CLI passes LOCAL_SCOPE (the
 * default 'local' tenant), preserving single-user behaviour while making
 * cross-tenant access structurally impossible once a real tenant is supplied.
 */
export interface AuthScope {
  tenantId: string;
}

export const LOCAL_TENANT = 'local';
export const LOCAL_SCOPE: AuthScope = { tenantId: LOCAL_TENANT };

export class CrossTenantAccessError extends Error {
  constructor(message = 'Resource not accessible in the current tenant scope') {
    super(message);
    this.name = 'CrossTenantAccessError';
  }
}

/** Build the tenant predicate for a scans query, optionally AND-ed with more. */
export function scanScopePredicate(scope: AuthScope, extra?: SQL): SQL {
  const tenant = eq(scans.tenantId, scope.tenantId);
  return extra ? (and(tenant, extra) as SQL) : tenant;
}
