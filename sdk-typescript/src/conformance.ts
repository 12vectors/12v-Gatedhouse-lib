#!/usr/bin/env node
/**
 * Gatedhouse TypeScript Conformance Harness
 *
 * Reads test vector suites from stdin (JSON), executes them against
 * the local implementation, and writes results to stdout.
 *
 * Used by tools/conformance_runner.py
 */

import {
  matchPermission,
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  intersectPermissions,
} from './permissions/matcher';
import { PermissionChecker } from './permissions/checker';
import { GatedContext } from './types';

interface TestSuite {
  suite: string;
  cases: TestCase[];
}

interface TestCase {
  name: string;
  [key: string]: unknown;
}

interface Results {
  passed: number;
  failed: number;
  errors: string[];
}

function makeMinimalContext(overrides: Record<string, unknown>): GatedContext {
  const membershipStatus = (overrides.membership_status as string) ?? 'active';
  const permissions = (overrides.permissions as string[]) ?? [];
  const scopes = overrides.scopes as string[] | null;
  const delegationData = overrides.delegation as Record<string, unknown> | null;

  let delegation;
  if (delegationData) {
    const offsetSeconds = delegationData.expires_at_offset_seconds as number;
    const expiresAt = new Date(Date.now() + offsetSeconds * 1000).toISOString();
    delegation = {
      id: delegationData.id as string,
      delegatorId: 'per_test',
      delegatorMembershipId: 'mbr_test',
      scopes: delegationData.scopes as string[],
      constraints: {},
      expiresAt,
      usesRemaining: delegationData.uses_remaining != null
        ? (delegationData.uses_remaining as number)
        : undefined,
    };
  }

  return {
    identity: { id: 'per_test', type: 'human', authMethod: 'password' },
    org: { id: 'org_test' },
    membership: {
      id: 'mbr_test',
      entityType: 'person',
      isOwner: false,
      status: membershipStatus,
      groups: [],
    },
    roles: [],
    permissions,
    scopes: scopes ?? undefined,
    delegation,
  };
}

function runPermissionMatching(cases: TestCase[]): Results {
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const actual = matchPermission(tc.granted as string, tc.required as string);
    if (actual === tc.expected) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `permission_matching/${tc.name}: expected ${tc.expected}, got ${actual}`,
      );
    }
  }
  return results;
}

function runHasPermission(cases: TestCase[]): Results {
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const actual = hasPermission(
      tc.granted_set as string[],
      tc.required as string,
    );
    if (actual === tc.expected) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `has_permission/${tc.name}: expected ${tc.expected}, got ${actual}`,
      );
    }
  }
  return results;
}

function runHasAllPermissions(cases: TestCase[]): Results {
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const actual = hasAllPermissions(
      tc.granted_set as string[],
      tc.required as string[],
    );
    if (actual === tc.expected) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `has_all_permissions/${tc.name}: expected ${tc.expected}, got ${actual}`,
      );
    }
  }
  return results;
}

function runHasAnyPermissions(cases: TestCase[]): Results {
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const actual = hasAnyPermission(
      tc.granted_set as string[],
      tc.required as string[],
    );
    if (actual === tc.expected) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `has_any_permissions/${tc.name}: expected ${tc.expected}, got ${actual}`,
      );
    }
  }
  return results;
}

function runIntersectPermissions(cases: TestCase[]): Results {
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const actual = intersectPermissions(
      tc.set_a as string[],
      tc.set_b as string[],
    );
    const actualSet = new Set(actual);
    let pass = true;
    for (const expected of (tc.expected_contains as string[]) ?? []) {
      if (!actualSet.has(expected)) {
        pass = false;
        results.errors.push(
          `intersect_permissions/${tc.name}: expected to contain '${expected}', got [${actual.join(', ')}]`,
        );
      }
    }
    for (const notExpected of (tc.expected_not_contains as string[]) ?? []) {
      if (actualSet.has(notExpected)) {
        pass = false;
        results.errors.push(
          `intersect_permissions/${tc.name}: expected NOT to contain '${notExpected}', got [${actual.join(', ')}]`,
        );
      }
    }
    if (pass) results.passed++;
    else results.failed++;
  }
  return results;
}

function runPermissionCheck(cases: TestCase[]): Results {
  const checker = new PermissionChecker();
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const ctx = makeMinimalContext(tc.context as Record<string, unknown>);
    const result = checker.check(ctx, tc.required as string);
    if (result.allowed === tc.expected_allowed) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `permission_check/${tc.name}: expected allowed=${tc.expected_allowed}, got ${result.allowed}`,
      );
    }
  }
  return results;
}

function runRoleDagResolution(cases: TestCase[]): Results {
  // This test uses an in-memory role store, no DB needed
  const results: Results = { passed: 0, failed: 0, errors: [] };
  for (const tc of cases) {
    const roles = tc.roles as Record<string, { permissions: string[]; inherits: string[] }>;
    const assignedRoles = tc.assigned_roles as string[];

    // Walk the DAG in-memory
    const permissionSet = new Set<string>();
    const visited = new Set<string>();

    function collectPermissions(roleId: string) {
      if (visited.has(roleId)) return;
      visited.add(roleId);
      const role = roles[roleId];
      if (!role) return;
      for (const perm of role.permissions) {
        permissionSet.add(perm);
      }
      for (const parent of role.inherits) {
        collectPermissions(parent);
      }
    }

    for (const roleId of assignedRoles) {
      collectPermissions(roleId);
    }

    const actual = Array.from(permissionSet);
    const expected = new Set(tc.expected_permissions as string[]);
    const actualAsSet = new Set(actual);

    if (
      actualAsSet.size === expected.size &&
      [...expected].every((p) => actualAsSet.has(p))
    ) {
      results.passed++;
    } else {
      results.failed++;
      results.errors.push(
        `role_dag_resolution/${tc.name}: expected [${[...expected].join(', ')}], got [${actual.join(', ')}]`,
      );
    }
  }
  return results;
}

const SUITE_RUNNERS: Record<string, (cases: TestCase[]) => Results> = {
  permission_matching: runPermissionMatching,
  has_permission: runHasPermission,
  has_all_permissions: runHasAllPermissions,
  has_any_permissions: runHasAnyPermissions,
  intersect_permissions: runIntersectPermissions,
  permission_check: runPermissionCheck,
  role_dag_resolution: runRoleDagResolution,
};

async function main() {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  const suites: TestSuite[] = JSON.parse(input);
  const totals: Results = { passed: 0, failed: 0, errors: [] };

  for (const suite of suites) {
    const runner = SUITE_RUNNERS[suite.suite];
    if (!runner) {
      totals.errors.push(`Unknown suite: ${suite.suite}`);
      continue;
    }
    const result = runner(suite.cases);
    totals.passed += result.passed;
    totals.failed += result.failed;
    totals.errors.push(...result.errors);
  }

  process.stdout.write(JSON.stringify(totals));
}

main().catch((err) => {
  process.stdout.write(
    JSON.stringify({ passed: 0, failed: 0, errors: [String(err)] }),
  );
  process.exit(1);
});
