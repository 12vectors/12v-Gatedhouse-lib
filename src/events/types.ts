/**
 * Event type constants for Citadel and Sphinx events.
 */

// Citadel organization events
export const ORG_CREATED = 'org.created';
export const ORG_DELETED = 'org.deleted';
export const ORG_SUSPENDED = 'org.suspended';
export const ORG_REACTIVATED = 'org.reactivated';

// Citadel membership events
export const MEMBERSHIP_CREATED = 'membership.created';
export const MEMBERSHIP_UPDATED = 'membership.updated';
export const MEMBERSHIP_SUSPENDED = 'membership.suspended';
export const MEMBERSHIP_REACTIVATED = 'membership.reactivated';
export const MEMBERSHIP_REMOVED = 'membership.removed';

// Citadel group events
export const GROUP_MEMBER_ADDED = 'group.member.added';
export const GROUP_MEMBER_REMOVED = 'group.member.removed';
export const GROUP_DELETED = 'group.deleted';

// Sphinx delegation events
export const DELEGATION_CREATED = 'delegation.created';
export const DELEGATION_REVOKED = 'delegation.revoked';
export const DELEGATION_EXPIRED = 'delegation.expired';
export const DELEGATION_EXHAUSTED = 'delegation.exhausted';
export const AGENT_DEACTIVATED = 'agent.deactivated';

export const ALL_EVENT_TYPES = [
  ORG_CREATED,
  ORG_DELETED,
  ORG_SUSPENDED,
  ORG_REACTIVATED,
  MEMBERSHIP_CREATED,
  MEMBERSHIP_UPDATED,
  MEMBERSHIP_SUSPENDED,
  MEMBERSHIP_REACTIVATED,
  MEMBERSHIP_REMOVED,
  GROUP_MEMBER_ADDED,
  GROUP_MEMBER_REMOVED,
  GROUP_DELETED,
  DELEGATION_CREATED,
  DELEGATION_REVOKED,
  DELEGATION_EXPIRED,
  DELEGATION_EXHAUSTED,
  AGENT_DEACTIVATED,
] as const;
