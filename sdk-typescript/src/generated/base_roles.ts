// AUTO-GENERATED from spec/schemas/
// Do not edit manually.

export const BASE_ROLES = [
  { key: 'owner', name: 'Owner', description: 'Organization owner with full access', permissions: ['*:*:*'], isSystem: true },
  { key: 'admin', name: 'Administrator', description: 'Organization administrator', permissions: ['*:*:*'], isSystem: true },
  { key: 'member', name: 'Member', description: 'Regular organization member', permissions: [], isSystem: true },
  { key: 'viewer', name: 'Viewer', description: 'Read-only access', permissions: [], isSystem: true },
] as const;

