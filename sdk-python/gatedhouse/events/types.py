"""Event type constants for Gatedhouse."""

# ─── Organization Events ────────────────────────────────────────────
ORG_CREATED = "org.created"
ORG_DELETED = "org.deleted"
ORG_SUSPENDED = "org.suspended"
ORG_REACTIVATED = "org.reactivated"

# ─── Membership Events ──────────────────────────────────────────────
MEMBERSHIP_CREATED = "membership.created"
MEMBERSHIP_UPDATED = "membership.updated"
MEMBERSHIP_SUSPENDED = "membership.suspended"
MEMBERSHIP_REACTIVATED = "membership.reactivated"
MEMBERSHIP_REMOVED = "membership.removed"

# ─── Group Events ───────────────────────────────────────────────────
GROUP_MEMBER_ADDED = "group.member.added"
GROUP_MEMBER_REMOVED = "group.member.removed"
GROUP_DELETED = "group.deleted"

# ─── Delegation Events ──────────────────────────────────────────────
DELEGATION_CREATED = "delegation.created"
DELEGATION_REVOKED = "delegation.revoked"
DELEGATION_EXPIRED = "delegation.expired"
DELEGATION_EXHAUSTED = "delegation.exhausted"
AGENT_DEACTIVATED = "agent.deactivated"

# ─── Audit Events ───────────────────────────────────────────────────
PERMISSION_CHECKED = "gatedhouse.permission.checked"
ROLE_CHANGED = "gatedhouse.role.changed"
