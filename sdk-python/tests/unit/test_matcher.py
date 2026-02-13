"""Tests for permission wildcard matching."""

from gatedhouse.core.permissions.matcher import (
    expand_wildcards,
    has_all_permissions,
    has_any_permission,
    has_permission,
    intersect_permissions,
    match_permission,
)


class TestMatchPermission:
    def test_exact_match(self) -> None:
        assert match_permission("files:documents:read", "files:documents:read") is True

    def test_exact_no_match(self) -> None:
        assert match_permission("files:documents:read", "files:documents:write") is False

    def test_wildcard_action(self) -> None:
        assert match_permission("files:documents:*", "files:documents:read") is True

    def test_wildcard_resource(self) -> None:
        assert match_permission("files:*:read", "files:documents:read") is True

    def test_wildcard_service(self) -> None:
        assert match_permission("*:documents:read", "files:documents:read") is True

    def test_superadmin(self) -> None:
        assert match_permission("*:*:*", "files:documents:read") is True

    def test_wildcard_no_match(self) -> None:
        assert match_permission("files:*:write", "files:documents:read") is False

    def test_non_standard_format_exact(self) -> None:
        assert match_permission("admin", "admin") is True

    def test_non_standard_format_no_match(self) -> None:
        assert match_permission("admin", "user") is False

    def test_two_segment(self) -> None:
        assert match_permission("files:read", "files:read") is True
        assert match_permission("files:read", "files:write") is False


class TestHasPermission:
    def test_has_permission(self) -> None:
        perms = ["files:documents:read", "files:documents:write"]
        assert has_permission(perms, "files:documents:read") is True

    def test_has_no_permission(self) -> None:
        perms = ["files:documents:read"]
        assert has_permission(perms, "files:documents:delete") is False

    def test_has_permission_wildcard(self) -> None:
        perms = ["files:*:*"]
        assert has_permission(perms, "files:documents:read") is True

    def test_empty_set(self) -> None:
        assert has_permission([], "files:documents:read") is False


class TestHasAllPermissions:
    def test_all_present(self) -> None:
        perms = ["files:documents:read", "files:documents:write"]
        assert has_all_permissions(perms, ["files:documents:read", "files:documents:write"]) is True

    def test_one_missing(self) -> None:
        perms = ["files:documents:read"]
        assert has_all_permissions(perms, ["files:documents:read", "files:documents:write"]) is False

    def test_wildcard_covers_all(self) -> None:
        perms = ["*:*:*"]
        assert has_all_permissions(perms, ["files:documents:read", "billing:invoices:write"]) is True


class TestHasAnyPermission:
    def test_one_present(self) -> None:
        perms = ["files:documents:read"]
        assert has_any_permission(perms, ["files:documents:read", "files:documents:write"]) is True

    def test_none_present(self) -> None:
        perms = ["billing:invoices:read"]
        assert has_any_permission(perms, ["files:documents:read", "files:documents:write"]) is False


class TestIntersectPermissions:
    def test_exact_overlap(self) -> None:
        result = intersect_permissions(
            ["files:documents:read", "files:documents:write"],
            ["files:documents:write", "billing:invoices:read"],
        )
        assert "files:documents:write" in result
        assert "files:documents:read" not in result
        assert "billing:invoices:read" not in result

    def test_wildcard_narrows(self) -> None:
        result = intersect_permissions(
            ["files:*:*"],
            ["files:documents:read", "billing:invoices:read"],
        )
        assert "files:documents:read" in result
        assert "billing:invoices:read" not in result

    def test_disjoint(self) -> None:
        result = intersect_permissions(
            ["files:documents:read"],
            ["billing:invoices:write"],
        )
        assert len(result) == 0

    def test_empty_set_a(self) -> None:
        result = intersect_permissions([], ["files:documents:read"])
        assert len(result) == 0

    def test_superadmin(self) -> None:
        result = intersect_permissions(
            ["*:*:*"],
            ["files:documents:read", "billing:invoices:write"],
        )
        assert "files:documents:read" in result
        assert "billing:invoices:write" in result


class TestExpandWildcards:
    def test_expand(self) -> None:
        result = expand_wildcards(
            ["files:*:*"],
            ["files:documents:read", "files:documents:write", "billing:invoices:read"],
        )
        assert "files:documents:read" in result
        assert "files:documents:write" in result
        assert "billing:invoices:read" not in result
        assert "files:*:*" in result  # wildcard kept

    def test_no_wildcards(self) -> None:
        result = expand_wildcards(
            ["files:documents:read"],
            ["files:documents:read", "files:documents:write"],
        )
        assert result == ["files:documents:read"]
