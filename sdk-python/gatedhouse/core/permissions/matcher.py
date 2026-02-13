"""Permission wildcard matching.

Permissions follow the format: {service}:{resource}:{action}
Wildcards (*) can match any segment.

Examples:
  - "files:documents:read" matches "files:documents:read" (exact)
  - "files:*:read" matches "files:documents:read" (resource wildcard)
  - "files:documents:*" matches "files:documents:read" (action wildcard)
  - "*:*:*" matches everything (superadmin)
"""

from __future__ import annotations


def match_permission(granted: str, required: str) -> bool:
    """Check if a granted permission matches a required permission."""
    if granted == required:
        return True

    granted_parts = granted.split(":")
    required_parts = required.split(":")

    # Both must be 3-segment format
    if len(granted_parts) != 3 or len(required_parts) != 3:
        return granted == required

    for g, r in zip(granted_parts, required_parts):
        if g == "*":
            continue
        if g != r:
            return False

    return True


def has_permission(granted_permissions: list[str] | tuple[str, ...], required: str) -> bool:
    """Check if a set of granted permissions satisfies a required permission."""
    return any(match_permission(g, required) for g in granted_permissions)


def has_all_permissions(
    granted_permissions: list[str] | tuple[str, ...], required: list[str] | tuple[str, ...]
) -> bool:
    """Check if a set of granted permissions satisfies all required permissions."""
    return all(has_permission(granted_permissions, r) for r in required)


def has_any_permission(
    granted_permissions: list[str] | tuple[str, ...], required: list[str] | tuple[str, ...]
) -> bool:
    """Check if a set of granted permissions satisfies any of the required permissions."""
    return any(has_permission(granted_permissions, r) for r in required)


def expand_wildcards(
    wildcard_permissions: list[str], known_permissions: list[str]
) -> list[str]:
    """Expand wildcard permissions against a set of known permissions."""
    expanded: set[str] = set()

    for granted in wildcard_permissions:
        if "*" not in granted:
            expanded.add(granted)
            continue
        for known in known_permissions:
            if match_permission(granted, known):
                expanded.add(known)
        # Also keep the wildcard itself for runtime matching
        expanded.add(granted)

    return list(expanded)


def intersect_permissions(
    set_a: list[str] | tuple[str, ...], set_b: list[str] | tuple[str, ...]
) -> list[str]:
    """Compute the intersection of two permission sets, respecting wildcards.

    Used for delegation three-way intersection.
    """
    result: list[str] = []

    for a in set_a:
        for b in set_b:
            if match_permission(a, b):
                # b is more specific or equal — keep b
                result.append(b)
            elif match_permission(b, a):
                # a is more specific — keep a
                result.append(a)

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for p in result:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped
