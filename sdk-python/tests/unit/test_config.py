"""Tests for configuration validation and resolution."""

import pytest

from gatedhouse.core.config import (
    DatabaseConfig,
    GatehouseConfig,
    resolve_config,
)


class TestResolveConfig:
    def test_valid_config(self) -> None:
        config = GatehouseConfig(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            database=DatabaseConfig(connection_string="postgresql://localhost/test"),
            service="test-service",
        )
        resolved = resolve_config(config)
        assert resolved.jwks_url == "https://auth.example.com/.well-known/jwks.json"
        assert resolved.service == "test-service"
        assert resolved.org_header == "X-Org-Id"
        assert resolved.default_role == "member"
        assert len(resolved.base_roles) == 4
        assert resolved.delegation.enabled is True

    def test_missing_jwks_url(self) -> None:
        config = GatehouseConfig(
            jwks_url="",
            database=DatabaseConfig(connection_string="postgresql://localhost/test"),
            service="test-service",
        )
        with pytest.raises(ValueError, match="jwks_url"):
            resolve_config(config)

    def test_missing_service(self) -> None:
        config = GatehouseConfig(
            jwks_url="https://auth.example.com/jwks",
            database=DatabaseConfig(connection_string="postgresql://localhost/test"),
            service="",
        )
        with pytest.raises(ValueError, match="service"):
            resolve_config(config)

    def test_custom_defaults(self) -> None:
        config = GatehouseConfig(
            jwks_url="https://auth.example.com/jwks",
            database=DatabaseConfig(connection_string="postgresql://localhost/test"),
            service="test-service",
            org_header="X-Tenant-Id",
            default_role="viewer",
            cache_miss_strategy="deny",
        )
        resolved = resolve_config(config)
        assert resolved.org_header == "X-Tenant-Id"
        assert resolved.default_role == "viewer"
        assert resolved.cache_miss_strategy == "deny"
