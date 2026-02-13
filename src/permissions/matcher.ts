/**
 * Permission wildcard matching.
 *
 * Permissions follow the format: {service}:{resource}:{action}
 * Wildcards (*) can match any segment.
 *
 * Examples:
 *   - "files:documents:read" matches "files:documents:read" (exact)
 *   - "files:*:read" matches "files:documents:read" (resource wildcard)
 *   - "files:documents:*" matches "files:documents:read" (action wildcard)
 *   - "*:*:*" matches everything (superadmin)
 */

export function matchPermission(
  granted: string,
  required: string,
): boolean {
  if (granted === required) return true;

  const grantedParts = granted.split(':');
  const requiredParts = required.split(':');

  // Both must be 3-segment format
  if (grantedParts.length !== 3 || requiredParts.length !== 3) {
    return granted === required;
  }

  for (let i = 0; i < 3; i++) {
    if (grantedParts[i] === '*') continue;
    if (grantedParts[i] !== requiredParts[i]) return false;
  }

  return true;
}

/**
 * Check if a set of granted permissions satisfies a required permission.
 */
export function hasPermission(
  grantedPermissions: string[],
  required: string,
): boolean {
  return grantedPermissions.some((granted) =>
    matchPermission(granted, required),
  );
}

/**
 * Check if a set of granted permissions satisfies all required permissions.
 */
export function hasAllPermissions(
  grantedPermissions: string[],
  required: string[],
): boolean {
  return required.every((r) => hasPermission(grantedPermissions, r));
}

/**
 * Check if a set of granted permissions satisfies any of the required permissions.
 */
export function hasAnyPermission(
  grantedPermissions: string[],
  required: string[],
): boolean {
  return required.some((r) => hasPermission(grantedPermissions, r));
}

/**
 * Expand wildcard permissions against a set of known permissions.
 * Used for materializing resolved permissions.
 */
export function expandWildcards(
  wildcardPermissions: string[],
  knownPermissions: string[],
): string[] {
  const expanded = new Set<string>();

  for (const granted of wildcardPermissions) {
    if (!granted.includes('*')) {
      expanded.add(granted);
      continue;
    }
    for (const known of knownPermissions) {
      if (matchPermission(granted, known)) {
        expanded.add(known);
      }
    }
    // Also keep the wildcard itself for runtime matching
    expanded.add(granted);
  }

  return Array.from(expanded);
}

/**
 * Compute the intersection of two permission sets, respecting wildcards.
 * Used for delegation three-way intersection.
 */
export function intersectPermissions(
  setA: string[],
  setB: string[],
): string[] {
  const result: string[] = [];

  for (const a of setA) {
    for (const b of setB) {
      if (matchPermission(a, b)) {
        // b is more specific or equal — keep b
        result.push(b);
      } else if (matchPermission(b, a)) {
        // a is more specific — keep a
        result.push(a);
      }
    }
  }

  // Deduplicate
  return [...new Set(result)];
}
