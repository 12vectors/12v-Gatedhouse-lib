#!/usr/bin/env python3
"""Gatedhouse Python Conformance Harness

Reads test vector suites from stdin (JSON), executes them against
the local implementation, and writes results to stdout.

Used by tools/conformance_runner.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from typing import Any

from gatedhouse.core.permissions.matcher import (
    match_permission,
    has_permission,
    has_all_permissions,
    has_any_permission,
    intersect_permissions,
)
from gatedhouse.core.permissions.checker import PermissionChecker
from gatedhouse.core.types import (
    DelegationContext,
    GatedContext,
    Identity,
    MembershipContext,
    OrgContext,
)


def make_minimal_context(overrides: dict[str, Any]) -> GatedContext:
    """Build a GatedContext from test case overrides."""
    membership_status = overrides.get("membership_status", "active")
    permissions = tuple(overrides.get("permissions", []))
    scopes_raw = overrides.get("scopes")
    scopes = tuple(scopes_raw) if scopes_raw is not None else None
    delegation_data = overrides.get("delegation")

    delegation = None
    if delegation_data:
        offset_seconds = delegation_data["expires_at_offset_seconds"]
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
        ).isoformat()

        uses_remaining = delegation_data.get("uses_remaining")
        # Convert null/None to None (Python handles this naturally)

        delegation = DelegationContext(
            id=delegation_data["id"],
            delegator_id="per_test",
            delegator_membership_id="mbr_test",
            scopes=tuple(delegation_data.get("scopes", [])),
            constraints={},
            expires_at=expires_at,
            uses_remaining=uses_remaining,
        )

    return GatedContext(
        identity=Identity(id="per_test", type="human", auth_method="password"),
        org=OrgContext(id="org_test"),
        membership=MembershipContext(
            id="mbr_test",
            entity_type="person",
            is_owner=False,
            status=membership_status,
            groups=(),
        ),
        roles=(),
        permissions=permissions,
        scopes=scopes,
        delegation=delegation,
    )


def run_permission_matching(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        actual = match_permission(tc["granted"], tc["required"])
        if actual == tc["expected"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"permission_matching/{tc['name']}: expected {tc['expected']}, got {actual}"
            )
    return results


def run_has_permission(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        actual = has_permission(tc["granted_set"], tc["required"])
        if actual == tc["expected"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"has_permission/{tc['name']}: expected {tc['expected']}, got {actual}"
            )
    return results


def run_has_all_permissions(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        actual = has_all_permissions(tc["granted_set"], tc["required"])
        if actual == tc["expected"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"has_all_permissions/{tc['name']}: expected {tc['expected']}, got {actual}"
            )
    return results


def run_has_any_permissions(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        actual = has_any_permission(tc["granted_set"], tc["required"])
        if actual == tc["expected"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"has_any_permissions/{tc['name']}: expected {tc['expected']}, got {actual}"
            )
    return results


def run_intersect_permissions(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        actual = intersect_permissions(tc["set_a"], tc["set_b"])
        actual_set = set(actual)
        passed = True

        for expected in tc.get("expected_contains", []):
            if expected not in actual_set:
                passed = False
                results["errors"].append(
                    f"intersect_permissions/{tc['name']}: expected to contain '{expected}', "
                    f"got [{', '.join(actual)}]"
                )

        for not_expected in tc.get("expected_not_contains", []):
            if not_expected in actual_set:
                passed = False
                results["errors"].append(
                    f"intersect_permissions/{tc['name']}: expected NOT to contain '{not_expected}', "
                    f"got [{', '.join(actual)}]"
                )

        if passed:
            results["passed"] += 1
        else:
            results["failed"] += 1
    return results


def run_permission_check(cases: list[dict]) -> dict:
    checker = PermissionChecker()
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        ctx = make_minimal_context(tc["context"])
        result = checker.check(ctx, tc["required"])
        if result.allowed == tc["expected_allowed"]:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"permission_check/{tc['name']}: expected allowed={tc['expected_allowed']}, "
                f"got {result.allowed}"
            )
    return results


def run_role_dag_resolution(cases: list[dict]) -> dict:
    results = {"passed": 0, "failed": 0, "errors": []}
    for tc in cases:
        roles = tc["roles"]
        assigned_roles = tc["assigned_roles"]

        permission_set: set[str] = set()
        visited: set[str] = set()

        def collect_permissions(role_id: str) -> None:
            if role_id in visited:
                return
            visited.add(role_id)
            role = roles.get(role_id)
            if not role:
                return
            permission_set.update(role["permissions"])
            for parent in role["inherits"]:
                collect_permissions(parent)

        for role_id in assigned_roles:
            collect_permissions(role_id)

        expected = set(tc["expected_permissions"])
        if permission_set == expected:
            results["passed"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(
                f"role_dag_resolution/{tc['name']}: expected [{', '.join(sorted(expected))}], "
                f"got [{', '.join(sorted(permission_set))}]"
            )
    return results


SUITE_RUNNERS = {
    "permission_matching": run_permission_matching,
    "has_permission": run_has_permission,
    "has_all_permissions": run_has_all_permissions,
    "has_any_permissions": run_has_any_permissions,
    "intersect_permissions": run_intersect_permissions,
    "permission_check": run_permission_check,
    "role_dag_resolution": run_role_dag_resolution,
}


def main() -> None:
    input_data = sys.stdin.read()
    suites = json.loads(input_data)

    totals = {"passed": 0, "failed": 0, "errors": []}

    for suite in suites:
        runner = SUITE_RUNNERS.get(suite["suite"])
        if not runner:
            totals["errors"].append(f"Unknown suite: {suite['suite']}")
            continue
        result = runner(suite["cases"])
        totals["passed"] += result["passed"]
        totals["failed"] += result["failed"]
        totals["errors"].extend(result["errors"])

    sys.stdout.write(json.dumps(totals))


if __name__ == "__main__":
    main()
