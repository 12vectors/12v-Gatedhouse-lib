# Copyright (c) 2026 12vectors.com
# SPDX-License-Identifier: MIT
# See the LICENSE file in the repository root for the full license text.

"""Database-free ``Gatedhouse`` implementation that only verifies tokens.

Mirrors the Java package-private ``JustTokenVerifierGatedhouse``; construct
via ``GatedhouseFactory.create_just_token_verifier``.
"""

from __future__ import annotations

from ._gatedhouse import Gatedhouse
from ._group_manager import GroupManager
from ._jwt_verification import JwtVerification
from ._membership_manager import MembershipManager
from ._permission_catalog import PermissionCatalog
from ._role_manager import RoleManager
from ._token_verifier_config import TokenVerifierConfig
from ._types import AuthenticatedSubject, EffectivePermission

_UNSUPPORTED = "Database operations not supported on token-verifier-only instance"


class JustTokenVerifierGatedhouse(Gatedhouse):

    def __init__(self, config: TokenVerifierConfig) -> None:
        if config is None:
            raise TypeError("config must not be None")
        self._jwt = JwtVerification(config)

    # ---- administrative sub-interfaces (unsupported) ----------------------

    def permission_catalog(self) -> PermissionCatalog:
        raise NotImplementedError(_UNSUPPORTED)

    def role_manager(self) -> RoleManager:
        raise NotImplementedError(_UNSUPPORTED)

    def membership_manager(self) -> MembershipManager:
        raise NotImplementedError(_UNSUPPORTED)

    def group_manager(self) -> GroupManager:
        raise NotImplementedError(_UNSUPPORTED)

    # ---- core check + reads (unsupported) ----------------------------------

    def has_permission(self, identity_id: str, org_id: str,
                       service: str, resource: str, action: str) -> bool:
        raise NotImplementedError(_UNSUPPORTED)

    def get_effective_permissions(self, identity_id: str,
                                  org_id: str) -> list[EffectivePermission]:
        raise NotImplementedError(_UNSUPPORTED)

    def get_roles(self, identity_id: str, org_id: str) -> list[str]:
        raise NotImplementedError(_UNSUPPORTED)

    def get_groups(self, identity_id: str, org_id: str) -> list[str]:
        raise NotImplementedError(_UNSUPPORTED)

    # ---- JWT verification --------------------------------------------------

    def verify_token(self, jwt_token: str) -> AuthenticatedSubject:
        return self._jwt.verify(jwt_token)

    # ---- cache control (no-ops: there is no cache) -------------------------

    def invalidate_cache(self, identity_id: str, org_id: str) -> None:
        pass

    def invalidate_all_cache(self) -> None:
        pass

    def set_cache_bypass(self, bypass: bool) -> None:
        pass

    def is_cache_bypassed(self) -> bool:
        return False

    # ---- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        pass
