"""Admin REST API router for role and permission management (FastAPI)."""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

logger = logging.getLogger("gatedhouse.admin")


def create_admin_router(gatedhouse: Any) -> Any:
    """Create a FastAPI APIRouter with admin endpoints for role management.

    Args:
        gatedhouse: The Gatedhouse orchestrator instance.

    Returns:
        A FastAPI APIRouter instance.
    """
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/gatedhouse/admin", tags=["gatedhouse-admin"])

    class RoleCreateRequest(BaseModel):
        key: str
        name: str
        description: str | None = None
        permissions: list[str] = []
        inherits: list[str] = []

    class RoleUpdateRequest(BaseModel):
        name: str
        description: str | None = None
        permissions: list[str] = []
        inherits: list[str] = []

    class RoleAssignRequest(BaseModel):
        membership_id: str
        role_id: str
        assigned_by: str | None = None

    class GroupRoleAssignRequest(BaseModel):
        group_id: str
        role_id: str
        assigned_by: str | None = None

    @router.get("/roles/{org_id}")
    async def list_roles(org_id: str) -> list[dict[str, Any]]:
        roles = await gatedhouse.role_repo.list_for_org(org_id)
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
                "inherits": r.inherits,
                "is_system": r.is_system,
            }
            for r in roles
        ]

    @router.post("/roles/{org_id}")
    async def create_role(org_id: str, body: RoleCreateRequest) -> dict[str, Any]:
        from gatedhouse.core.types import RoleDefinition
        role = RoleDefinition(
            key=body.key, name=body.name, description=body.description,
            permissions=body.permissions, inherits=body.inherits,
        )
        stored = await gatedhouse.role_repo.create(org_id, role)
        return {"id": stored.id, "name": stored.name}

    @router.get("/roles/{org_id}/{role_id}")
    async def get_role(org_id: str, role_id: str) -> dict[str, Any]:
        role = await gatedhouse.role_repo.find_by_id(org_id, role_id)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return {
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "permissions": role.permissions,
            "inherits": role.inherits,
            "is_system": role.is_system,
        }

    @router.put("/roles/{org_id}/{role_id}")
    async def update_role(
        org_id: str, role_id: str, body: RoleUpdateRequest
    ) -> dict[str, Any]:
        from gatedhouse.core.types import RoleDefinition
        role = RoleDefinition(
            key=role_id, name=body.name, description=body.description,
            permissions=body.permissions, inherits=body.inherits,
        )
        stored = await gatedhouse.role_repo.update(org_id, role_id, role)
        if not stored:
            raise HTTPException(status_code=404, detail="Role not found")
        return {"id": stored.id, "name": stored.name}

    @router.delete("/roles/{org_id}/{role_id}")
    async def delete_role(org_id: str, role_id: str) -> dict[str, str]:
        deleted = await gatedhouse.role_repo.delete(org_id, role_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Role not found or is system role")
        return {"status": "deleted"}

    @router.post("/assignments/{org_id}")
    async def assign_role(org_id: str, body: RoleAssignRequest) -> dict[str, str]:
        await gatedhouse.role_assignments.assign(
            body.membership_id, body.role_id, org_id, body.assigned_by
        )
        return {"status": "assigned"}

    @router.delete("/assignments/{org_id}/{membership_id}/{role_id}")
    async def revoke_role(
        org_id: str, membership_id: str, role_id: str
    ) -> dict[str, str]:
        await gatedhouse.role_assignments.revoke(membership_id, role_id)
        return {"status": "revoked"}

    @router.post("/group-assignments/{org_id}")
    async def assign_group_role(org_id: str, body: GroupRoleAssignRequest) -> dict[str, str]:
        await gatedhouse.role_assignments.assign_to_group(
            body.group_id, body.role_id, org_id, body.assigned_by
        )
        return {"status": "assigned"}

    @router.delete("/group-assignments/{org_id}/{group_id}/{role_id}")
    async def revoke_group_role(
        org_id: str, group_id: str, role_id: str
    ) -> dict[str, str]:
        await gatedhouse.role_assignments.revoke_from_group(group_id, role_id)
        return {"status": "revoked"}

    @router.get("/permissions/{membership_id}")
    async def get_permissions(membership_id: str) -> dict[str, Any]:
        resolved = await gatedhouse.permission_resolver.get_cached_permissions(membership_id)
        return {
            "membership_id": membership_id,
            "permissions": [
                {"permission": r.permission, "source": r.source}
                for r in resolved
            ],
        }

    @router.post("/permissions/{membership_id}/rebuild")
    async def rebuild_permissions(membership_id: str, org_id: str) -> dict[str, Any]:
        cached = await gatedhouse.membership_cache.find_by_id(membership_id)
        groups = cached.groups if cached else []
        permissions = await gatedhouse.permission_resolver.rebuild_for_membership(
            membership_id, org_id, groups
        )
        return {"membership_id": membership_id, "count": len(permissions)}

    return router
