// AUTO-GENERATED from spec/schemas/events_catalog.json
// Do not edit manually. Run: python spec/codegen/generate.py --target typescript

// Citadel events
export const ORG_CREATED = 'org.created';
export const ORG_DELETED = 'org.deleted';
export const ORG_SUSPENDED = 'org.suspended';
export const ORG_REACTIVATED = 'org.reactivated';
export const MEMBERSHIP_CREATED = 'membership.created';
export const MEMBERSHIP_UPDATED = 'membership.updated';
export const MEMBERSHIP_SUSPENDED = 'membership.suspended';
export const MEMBERSHIP_REACTIVATED = 'membership.reactivated';
export const MEMBERSHIP_REMOVED = 'membership.removed';
export const GROUP_MEMBER_ADDED = 'group.member.added';
export const GROUP_MEMBER_REMOVED = 'group.member.removed';
export const GROUP_DELETED = 'group.deleted';

// Sphinx events
export const DELEGATION_CREATED = 'delegation.created';
export const DELEGATION_REVOKED = 'delegation.revoked';
export const DELEGATION_EXPIRED = 'delegation.expired';
export const DELEGATION_EXHAUSTED = 'delegation.exhausted';
export const AGENT_DEACTIVATED = 'agent.deactivated';

// Audit events
export const AUTHZ_DECISION_ALLOWED = 'authz.decision.allowed';
export const AUTHZ_DECISION_DENIED = 'authz.decision.denied';

export const ALL_CITADEL_EVENTS = [
  'org.created',
  'org.deleted',
  'org.suspended',
  'org.reactivated',
  'membership.created',
  'membership.updated',
  'membership.suspended',
  'membership.reactivated',
  'membership.removed',
  'group.member.added',
  'group.member.removed',
  'group.deleted',
] as const;

export const ALL_SPHINX_EVENTS = [
  'delegation.created',
  'delegation.revoked',
  'delegation.expired',
  'delegation.exhausted',
  'agent.deactivated',
] as const;

