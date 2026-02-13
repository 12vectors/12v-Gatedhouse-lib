//! Event type constants for Gatedhouse.

// ─── Organization Events ────────────────────────────────────────────
pub const ORG_CREATED: &str = "org.created";
pub const ORG_DELETED: &str = "org.deleted";
pub const ORG_SUSPENDED: &str = "org.suspended";
pub const ORG_REACTIVATED: &str = "org.reactivated";

// ─── Membership Events ──────────────────────────────────────────────
pub const MEMBERSHIP_CREATED: &str = "membership.created";
pub const MEMBERSHIP_UPDATED: &str = "membership.updated";
pub const MEMBERSHIP_SUSPENDED: &str = "membership.suspended";
pub const MEMBERSHIP_REACTIVATED: &str = "membership.reactivated";
pub const MEMBERSHIP_REMOVED: &str = "membership.removed";

// ─── Group Events ───────────────────────────────────────────────────
pub const GROUP_MEMBER_ADDED: &str = "group.member.added";
pub const GROUP_MEMBER_REMOVED: &str = "group.member.removed";
pub const GROUP_DELETED: &str = "group.deleted";

// ─── Delegation Events ──────────────────────────────────────────────
pub const DELEGATION_CREATED: &str = "delegation.created";
pub const DELEGATION_REVOKED: &str = "delegation.revoked";
pub const DELEGATION_EXPIRED: &str = "delegation.expired";
pub const DELEGATION_EXHAUSTED: &str = "delegation.exhausted";
pub const AGENT_DEACTIVATED: &str = "agent.deactivated";

// ─── Audit Events ───────────────────────────────────────────────────
pub const PERMISSION_CHECKED: &str = "gatedhouse.permission.checked";
pub const ROLE_CHANGED: &str = "gatedhouse.role.changed";
