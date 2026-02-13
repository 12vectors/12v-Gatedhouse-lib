# Gatedhouse Library Skills Guide

## Overview

**Gatedhouse** is an embedded authorization library providing RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control) for the SuperAgent Platform. It delivers sub-microsecond authorization decisions by embedding directly in services, eliminating per-request network hops.

### Multi-Language Support

The library provides feature-complete SDKs in:
- **TypeScript/JavaScript** (fully implemented)
- **Python** (fully implemented)
- **Rust** (in progress)

All SDKs share a common specification and are guaranteed behaviorally consistent through exhaustive conformance testing.

---

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Prerequisites](#prerequisites)
3. [Step-by-Step Implementation Sequence](#step-by-step-implementation-sequence)
4. [Detailed Capabilities](#detailed-capabilities)
5. [Common Use Cases](#common-use-cases)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Topics](#advanced-topics)

---

## Core Concepts

### Authorization Model

Gatedhouse uses a hierarchical permission model:

```
{service}:{resource}:{action}
```

Examples:
- `workspace:projects:create`
- `workspace:documents:read`
- `admin:users:delete`
- `workspace:*:read` (wildcard: read any workspace resource)
- `*:*:*` (superuser: all permissions)

### Key Components

1. **Identity**: The authenticated user/agent/machine
2. **Membership**: User's relationship to an organization (includes groups, ownership, status)
3. **Roles**: Named collections of permissions with inheritance support
4. **Delegation**: Temporary authority transfer from one identity to another
5. **Scopes**: Permission constraints for API keys and client credentials
6. **Policies**: Custom authorization logic beyond role-based checks

### Authorization Decision Flow

```
Request → JWT Verification → Membership Lookup → Role Resolution → Permission Check → Allow/Deny
```

With optional layers:
- **Scoped Access**: API key/credential scopes ∩ role permissions
- **Delegation**: Three-way intersection of delegation scopes ∩ agent permissions ∩ delegator permissions
- **Custom Policies**: User-defined authorization logic

---

## Prerequisites

### Database Requirements

- **PostgreSQL 12+** (required for all SDKs)
- Connection pooling recommended for production

### Language-Specific Requirements

#### TypeScript/JavaScript
```json
{
  "node": ">=18.0.0",
  "dependencies": {
    "jose": "^5.2.0",
    "pg": "^8.12.0",
    "pino": "^8.18.0"
  },
  "peerDependencies": {
    "express": "^4.18.0"
  }
}
```

#### Python
```toml
[project]
requires-python = ">=3.11"
dependencies = [
    "asyncpg>=0.29.0",
    "PyJWT[crypto]>=2.8.0",
    "httpx>=0.27.0"
]

[project.optional-dependencies]
fastapi = ["fastapi>=0.110.0"]
django = ["django>=4.2.0"]
```

#### Rust
```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-native-tls"] }
serde = { version = "1.0", features = ["derive"] }
jsonwebtoken = "9"
```

---

## Step-by-Step Implementation Sequence

### Phase 1: Database Setup

**Step 1.1: Run Database Migrations**

The shared SQL schema is in `spec/sql/migrations/001_initial_schema.sql`. This creates 7 tables:

```sql
gatedhouse_roles                 -- Role definitions
gatedhouse_role_assignments      -- Identity → Role mappings
gatedhouse_group_roles           -- Group → Role mappings
gatedhouse_permissions           -- Permission catalog
gatedhouse_membership_cache      -- Synced from Citadel
gatedhouse_delegation_cache      -- Synced from Sphinx
gatedhouse_resolved_permissions  -- Materialized permissions
```

**TypeScript:**
```bash
npm install
npx tsx src/cli/migrate.ts up
```

**Python:**
```bash
pip install -e .
python -m gatedhouse.cli.migrate up
```

**Rust:**
```bash
cargo run --bin migrate -- up
```

**Step 1.2: Verify Schema**

Query to confirm tables exist:
```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name LIKE 'gatedhouse_%';
```

Should return 7 tables.

---

### Phase 2: Configuration

**Step 2.1: Create Configuration File**

The configuration schema is in `spec/schemas/config.json`. All SDKs accept configuration in this format:

**TypeScript (`config.ts`):**
```typescript
import { Gatedhouse } from '@gatedhouse/sdk';

const gatedhouse = new Gatedhouse({
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME || 'gatedhouse',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    ssl: process.env.DB_SSL === 'true',
    poolSize: 20
  },
  jwt: {
    jwksUri: 'https://auth.example.com/.well-known/jwks.json',
    issuer: 'https://auth.example.com',
    audience: 'api://default',
    cacheTtl: 3600 // JWKS cache TTL in seconds
  },
  events: {
    adapter: 'in-memory', // or custom adapter
    enabled: true
  },
  audit: {
    enabled: true,
    logDenials: true,
    logSuccesses: false // Only log denials in production
  },
  metrics: {
    enabled: true
  },
  logging: {
    level: 'info', // trace, debug, info, warn, error
    pretty: process.env.NODE_ENV !== 'production'
  }
});

export default gatedhouse;
```

**Python (`config.py`):**
```python
from gatedhouse import Gatedhouse, Config, DatabaseConfig, JwtConfig

config = Config(
    database=DatabaseConfig(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "gatedhouse"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
        ssl=os.getenv("DB_SSL") == "true",
        pool_size=20
    ),
    jwt=JwtConfig(
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        issuer="https://auth.example.com",
        audience="api://default",
        cache_ttl=3600
    ),
    events={"adapter": "in-memory", "enabled": True},
    audit={"enabled": True, "log_denials": True, "log_successes": False},
    metrics={"enabled": True},
    logging={"level": "info"}
)

gatedhouse = Gatedhouse(config)
```

**Rust (`main.rs`):**
```rust
use gatedhouse::{Gatedhouse, Config, DatabaseConfig, JwtConfig};

let config = Config {
    database: DatabaseConfig {
        host: env::var("DB_HOST").unwrap_or("localhost".into()),
        port: env::var("DB_PORT").unwrap_or("5432".into()).parse()?,
        database: env::var("DB_NAME").unwrap_or("gatedhouse".into()),
        user: env::var("DB_USER").unwrap_or("postgres".into()),
        password: env::var("DB_PASSWORD").ok(),
        ssl: env::var("DB_SSL").is_ok(),
        pool_size: 20,
    },
    jwt: JwtConfig {
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".into(),
        issuer: "https://auth.example.com".into(),
        audience: "api://default".into(),
        cache_ttl: 3600,
    },
    events: serde_json::json!({"adapter": "in-memory", "enabled": true}),
    audit: serde_json::json!({"enabled": true, "log_denials": true}),
    metrics: serde_json::json!({"enabled": true}),
    logging: serde_json::json!({"level": "info"}),
};

let gatedhouse = Gatedhouse::new(config).await?;
```

**Step 2.2: Initialize the Library**

After creating the configuration, initialize the library:

**TypeScript:**
```typescript
await gatedhouse.initialize();
```

**Python:**
```python
await gatedhouse.initialize()
```

**Rust:**
```rust
gatedhouse.initialize().await?;
```

This:
- Establishes database connection pool
- Fetches JWKS keys
- Starts event listeners
- Initializes caches

---

### Phase 3: Define Roles and Permissions

**Step 3.1: Register Permissions**

The permission catalog defines all available permissions in your system:

**TypeScript:**
```typescript
import { PermissionRegistry } from '@gatedhouse/sdk';

const registry = new PermissionRegistry();

// Register workspace permissions
registry.register('workspace:projects:create', {
  service: 'workspace',
  resource: 'projects',
  action: 'create',
  description: 'Create new projects'
});

registry.register('workspace:projects:read', {
  service: 'workspace',
  resource: 'projects',
  action: 'read',
  description: 'View projects'
});

registry.register('workspace:projects:update', {
  service: 'workspace',
  resource: 'projects',
  action: 'update',
  description: 'Update project details'
});

registry.register('workspace:projects:delete', {
  service: 'workspace',
  resource: 'projects',
  action: 'delete',
  description: 'Delete projects'
});

// Register admin permissions
registry.register('admin:users:*', {
  service: 'admin',
  resource: 'users',
  action: '*',
  description: 'All user management operations'
});

await registry.save(gatedhouse.database);
```

**Python:**
```python
from gatedhouse.core.permissions import PermissionRegistry

registry = PermissionRegistry()

registry.register("workspace:projects:create",
    service="workspace",
    resource="projects",
    action="create",
    description="Create new projects"
)

registry.register("workspace:projects:read",
    service="workspace",
    resource="projects",
    action="read",
    description="View projects"
)

await registry.save(gatedhouse.database)
```

**Step 3.2: Define Roles**

Create role definitions with inheritance:

**TypeScript:**
```typescript
import { RoleRepository } from '@gatedhouse/sdk';

const roleRepo = new RoleRepository(gatedhouse.database);

// Define base role
await roleRepo.create({
  key: 'viewer',
  name: 'Viewer',
  permissions: [
    'workspace:*:read'
  ],
  isSystem: false
});

// Define role with inheritance
await roleRepo.create({
  key: 'editor',
  name: 'Editor',
  inherits: ['viewer'], // Inherits all viewer permissions
  permissions: [
    'workspace:projects:create',
    'workspace:projects:update',
    'workspace:documents:create',
    'workspace:documents:update'
  ]
});

// Define admin role
await roleRepo.create({
  key: 'admin',
  name: 'Administrator',
  inherits: ['editor'],
  permissions: [
    'workspace:*:delete',
    'admin:*:*'
  ],
  isSystem: false
});

// Define owner role (automatic assignment)
await roleRepo.create({
  key: 'owner',
  name: 'Owner',
  inherits: ['admin'],
  permissions: [
    '*:*:*' // Superuser
  ],
  isSystem: true
});
```

**Python:**
```python
from gatedhouse.core.roles import RoleRepository

role_repo = RoleRepository(gatedhouse.database)

await role_repo.create(
    key="viewer",
    name="Viewer",
    permissions=["workspace:*:read"],
    is_system=False
)

await role_repo.create(
    key="editor",
    name="Editor",
    inherits=["viewer"],
    permissions=[
        "workspace:projects:create",
        "workspace:projects:update"
    ]
)

await role_repo.create(
    key="admin",
    name="Administrator",
    inherits=["editor"],
    permissions=[
        "workspace:*:delete",
        "admin:*:*"
    ]
)
```

**Step 3.3: Visualize Role Hierarchy**

The role inheritance creates a DAG (Directed Acyclic Graph):

```
owner
  ↓ (inherits)
admin
  ↓
editor
  ↓
viewer
```

Effective permissions for "editor" include:
- Direct: `workspace:projects:create`, `workspace:projects:update`, ...
- Inherited from viewer: `workspace:*:read`

---

### Phase 4: Assign Roles to Users

**Step 4.1: Assign Roles to Identities**

**TypeScript:**
```typescript
import { RoleAssignment } from '@gatedhouse/sdk';

const assignment = new RoleAssignment(gatedhouse.database);

// Assign role to user in specific organization
await assignment.assign({
  identityId: 'per_01HQXYZ...', // ULID of user
  orgId: 'org_01HQXYZ...',
  roleKey: 'editor',
  assignedBy: 'per_01ADMIN...', // Who granted this role
  expiresAt: null // No expiration
});

// Temporary role assignment
await assignment.assign({
  identityId: 'per_01HQXYZ...',
  orgId: 'org_01HQXYZ...',
  roleKey: 'admin',
  assignedBy: 'per_01ADMIN...',
  expiresAt: new Date('2026-12-31') // Expires at end of year
});
```

**Python:**
```python
from gatedhouse.core.roles import RoleAssignment

assignment = RoleAssignment(gatedhouse.database)

await assignment.assign(
    identity_id="per_01HQXYZ...",
    org_id="org_01HQXYZ...",
    role_key="editor",
    assigned_by="per_01ADMIN...",
    expires_at=None
)
```

**Step 4.2: Assign Roles to Groups**

For group-based permissions:

**TypeScript:**
```typescript
await assignment.assignToGroup({
  groupId: 'grp_01HQXYZ...',
  orgId: 'org_01HQXYZ...',
  roleKey: 'viewer'
});
```

All members of the group automatically inherit the role.

---

### Phase 5: Framework Integration

#### Option A: Express (TypeScript)

**Step 5.1: Add Middleware**

```typescript
import express from 'express';
import { Gatedhouse, createExpressMiddleware } from '@gatedhouse/sdk';

const app = express();
const gatedhouse = new Gatedhouse(config);

await gatedhouse.initialize();

// Apply middleware to populate req.gatedContext
app.use(createExpressMiddleware(gatedhouse));

// Use in routes
app.get('/api/projects', async (req, res) => {
  // req.gatedContext is now available
  if (!req.gatedContext.permissions.includes('workspace:projects:read')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Handle request...
});
```

**Step 5.2: Use Permission Guards**

```typescript
import { requirePermission, requireAllPermissions, requireAnyPermission } from '@gatedhouse/sdk';

// Single permission
app.post('/api/projects',
  requirePermission('workspace:projects:create'),
  async (req, res) => {
    // User has permission, proceed
  }
);

// All permissions required
app.delete('/api/projects/:id',
  requireAllPermissions([
    'workspace:projects:read',
    'workspace:projects:delete'
  ]),
  async (req, res) => {
    // User has all permissions
  }
);

// Any permission required
app.get('/api/admin',
  requireAnyPermission([
    'admin:*:*',
    'owner:*:*'
  ]),
  async (req, res) => {
    // User has at least one permission
  }
);
```

#### Option B: FastAPI (Python)

**Step 5.1: Add Middleware**

```python
from fastapi import FastAPI, Request, Depends
from gatedhouse import Gatedhouse
from gatedhouse.middleware.fastapi import GatedhouseMiddleware, require_permission

app = FastAPI()
gatedhouse = Gatedhouse(config)

await gatedhouse.initialize()

# Add middleware
app.add_middleware(GatedhouseMiddleware, gatedhouse=gatedhouse)

# Use dependency injection
@app.get("/api/projects")
async def get_projects(request: Request):
    if "workspace:projects:read" not in request.state.gated_context.permissions:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Handle request...
```

**Step 5.2: Use Permission Decorators**

```python
from gatedhouse.middleware.fastapi import require_permission, require_all_permissions

@app.post("/api/projects")
@require_permission("workspace:projects:create")
async def create_project(request: Request):
    # User has permission
    pass

@app.delete("/api/projects/{project_id}")
@require_all_permissions([
    "workspace:projects:read",
    "workspace:projects:delete"
])
async def delete_project(request: Request, project_id: str):
    # User has all permissions
    pass
```

#### Option C: Django (Python)

**Step 5.1: Add Middleware**

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    'gatedhouse.middleware.django.GatedhouseMiddleware',
]

GATEDHOUSE_CONFIG = {
    'database': {
        'host': 'localhost',
        # ... config
    },
    'jwt': {
        # ... config
    }
}
```

**Step 5.2: Use Decorators**

```python
from django.http import JsonResponse
from gatedhouse.middleware.django import require_permission

@require_permission("workspace:projects:create")
def create_project(request):
    # User has permission
    return JsonResponse({"status": "ok"})
```

#### Option D: Axum (Rust)

**Step 5.1: Add Middleware**

```rust
use axum::{Router, middleware};
use gatedhouse::middleware::axum::{gatedhouse_middleware, RequirePermission};

let app = Router::new()
    .route("/api/projects", get(get_projects))
    .layer(middleware::from_fn_with_state(
        gatedhouse.clone(),
        gatedhouse_middleware
    ));
```

**Step 5.2: Use Guards**

```rust
async fn create_project(
    Extension(ctx): Extension<GatedContext>,
) -> Result<Json<Project>, StatusCode> {
    if !ctx.permissions.contains(&"workspace:projects:create".to_string()) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Handle request
}
```

---

### Phase 6: Membership and Delegation Sync

**Step 6.1: Sync Membership Cache from Citadel**

The membership cache stores user-org relationships:

**TypeScript:**
```typescript
import { MembershipCache } from '@gatedhouse/sdk';

const membershipCache = new MembershipCache(gatedhouse.database);

// Sync from Citadel (called by event handler)
await membershipCache.upsert({
  id: 'mem_01HQXYZ...',
  identityId: 'per_01HQXYZ...',
  orgId: 'org_01HQXYZ...',
  entityType: 'user',
  isOwner: false,
  status: 'active', // active | suspended | pending
  groups: ['grp_01SALES...', 'grp_01ENGINEERING...'],
  metadata: { joinedAt: '2025-01-15T10:00:00Z' }
});

// Lookup membership
const membership = await membershipCache.get('per_01HQXYZ...', 'org_01HQXYZ...');

// Resolve groups
const groups = await membershipCache.getGroups('per_01HQXYZ...', 'org_01HQXYZ...');
```

**Python:**
```python
from gatedhouse.core.membership import MembershipCache

cache = MembershipCache(gatedhouse.database)

await cache.upsert(
    id="mem_01HQXYZ...",
    identity_id="per_01HQXYZ...",
    org_id="org_01HQXYZ...",
    entity_type="user",
    is_owner=False,
    status="active",
    groups=["grp_01SALES...", "grp_01ENGINEERING..."],
    metadata={"joined_at": "2025-01-15T10:00:00Z"}
)
```

**Step 6.2: Sync Delegation Cache from Sphinx**

The delegation cache stores temporary authority transfers:

**TypeScript:**
```typescript
import { DelegationCache } from '@gatedhouse/sdk';

const delegationCache = new DelegationCache(gatedhouse.database);

// Sync delegation from Sphinx
await delegationCache.upsert({
  id: 'del_01HQXYZ...',
  delegatorId: 'per_01ALICE...', // Who delegated authority
  agentId: 'agt_01BOB...', // Who received authority
  orgId: 'org_01HQXYZ...',
  scopes: [
    'workspace:projects:read',
    'workspace:projects:update'
  ], // Constrained permissions
  constraints: {
    maxPermissions: ['workspace:*:*'], // Agent can't exceed these
    resourceIds: ['proj_123', 'proj_456'] // Limit to specific resources
  },
  expiresAt: new Date('2026-02-20T23:59:59Z'),
  usesRemaining: 100, // Decremented on each use
  metadata: { reason: 'vacation coverage' }
});

// Check if delegation is valid
const isValid = await delegationCache.isValid('del_01HQXYZ...');

// Decrement use counter
await delegationCache.decrementUses('del_01HQXYZ...');
```

**Python:**
```python
from gatedhouse.core.delegation import DelegationCache

cache = DelegationCache(gatedhouse.database)

await cache.upsert(
    id="del_01HQXYZ...",
    delegator_id="per_01ALICE...",
    agent_id="agt_01BOB...",
    org_id="org_01HQXYZ...",
    scopes=[
        "workspace:projects:read",
        "workspace:projects:update"
    ],
    constraints={
        "max_permissions": ["workspace:*:*"],
        "resource_ids": ["proj_123", "proj_456"]
    },
    expires_at="2026-02-20T23:59:59Z",
    uses_remaining=100
)
```

---

### Phase 7: Authorization Checks

**Step 7.1: Standard Permission Check**

**TypeScript:**
```typescript
import { PermissionChecker } from '@gatedhouse/sdk';

const checker = new PermissionChecker(gatedhouse);

// Simple check
const canCreate = await checker.check(
  gatedContext,
  'workspace:projects:create'
);

if (!canCreate) {
  throw new Error('Forbidden');
}

// Check with resource context
const canDelete = await checker.check(
  gatedContext,
  'workspace:projects:delete',
  { projectId: 'proj_123' }
);
```

**Python:**
```python
from gatedhouse.core.permissions import PermissionChecker

checker = PermissionChecker(gatedhouse)

can_create = await checker.check(
    gated_context,
    "workspace:projects:create"
)

if not can_create:
    raise PermissionError("Forbidden")
```

**Step 7.2: Check Multiple Permissions**

**TypeScript:**
```typescript
// All-of (AND logic)
const hasAll = await checker.checkAll(gatedContext, [
  'workspace:projects:read',
  'workspace:projects:update'
]);

// Any-of (OR logic)
const hasAny = await checker.checkAny(gatedContext, [
  'admin:*:*',
  'owner:*:*'
]);
```

**Step 7.3: Scoped Access Check (API Keys)**

When a user authenticates with an API key, their effective permissions are constrained by the key's scopes:

**TypeScript:**
```typescript
// User has roles: ['admin'] → permissions: ['workspace:*:*', 'admin:*:*']
// API key scopes: ['workspace:projects:read', 'workspace:projects:update']

// Effective permissions = role permissions ∩ API key scopes
const result = await checker.check(
  gatedContext, // includes scopes from API key
  'workspace:projects:read' // ✓ Allowed (in scopes)
);

const result2 = await checker.check(
  gatedContext,
  'admin:users:delete' // ✗ Denied (not in scopes)
);
```

**Step 7.4: Delegated Authority Check**

Three-way intersection: delegation scopes ∩ agent max permissions ∩ delegator current permissions

**TypeScript:**
```typescript
// Alice (delegator) has: ['workspace:*:*', 'admin:*:*']
// Bob (agent) max permissions: ['workspace:projects:*', 'workspace:docs:read']
// Delegation scopes: ['workspace:projects:read', 'workspace:projects:update']

// Effective permissions = ALL THREE intersected
const result = await checker.check(
  bobGatedContext, // includes delegation
  'workspace:projects:read' // ✓ Allowed
);

const result2 = await checker.check(
  bobGatedContext,
  'workspace:projects:delete' // ✗ Denied (not in delegation scopes)
);

const result3 = await checker.check(
  bobGatedContext,
  'admin:users:read' // ✗ Denied (not in agent max permissions)
);
```

---

### Phase 8: Custom Policies

**Step 8.1: Register Policy Functions**

For authorization logic beyond role-based checks:

**TypeScript:**
```typescript
import { PolicyEngine } from '@gatedhouse/sdk';

const policyEngine = new PolicyEngine();

// Resource ownership policy
policyEngine.register('resource.is_owner', async (ctx, resource) => {
  // ctx: GatedContext
  // resource: { projectId, ownerId, ... }
  return ctx.identity.id === resource.ownerId;
});

// Time-based policy
policyEngine.register('time.business_hours', async (ctx, resource) => {
  const hour = new Date().getHours();
  return hour >= 9 && hour < 17;
});

// Geo-restriction policy
policyEngine.register('geo.us_only', async (ctx, resource) => {
  const ipCountry = ctx.identity.metadata?.ipCountry;
  return ipCountry === 'US';
});

// Custom logic
policyEngine.register('project.is_collaborator', async (ctx, resource) => {
  const project = await db.getProject(resource.projectId);
  return project.collaborators.includes(ctx.identity.id);
});
```

**Step 8.2: Use Policies in Authorization**

**TypeScript:**
```typescript
const checker = new PermissionChecker(gatedhouse, policyEngine);

// Check permission + policy
const canDelete = await checker.check(
  gatedContext,
  'workspace:projects:delete',
  { projectId: 'proj_123', ownerId: 'per_01ALICE...' },
  ['resource.is_owner'] // Policy must pass
);

// Multiple policies (all must pass)
const canAccess = await checker.check(
  gatedContext,
  'workspace:projects:read',
  { projectId: 'proj_123' },
  ['time.business_hours', 'geo.us_only']
);
```

**Python:**
```python
from gatedhouse.core.policies import PolicyEngine

engine = PolicyEngine()

@engine.register("resource.is_owner")
async def check_ownership(ctx, resource):
    return ctx.identity.id == resource.get("owner_id")

checker = PermissionChecker(gatedhouse, engine)

can_delete = await checker.check(
    gated_context,
    "workspace:projects:delete",
    {"project_id": "proj_123", "owner_id": "per_01ALICE..."},
    policies=["resource.is_owner"]
)
```

---

### Phase 9: Event Handling

**Step 9.1: Register Event Handlers**

Listen for authorization events to invalidate caches:

**TypeScript:**
```typescript
import { EventHandlerRegistry } from '@gatedhouse/sdk';

const events = new EventHandlerRegistry(gatedhouse);

// Handle role changes
events.on('role.created', async (event) => {
  // Invalidate resolved permissions cache
  await gatedhouse.invalidateCache('roles');
});

events.on('role.updated', async (event) => {
  await gatedhouse.invalidateCache('roles');
});

events.on('role.deleted', async (event) => {
  await gatedhouse.invalidateCache('roles');
});

// Handle assignment changes
events.on('assignment.created', async (event) => {
  const { identityId, orgId } = event.payload;
  await gatedhouse.invalidateCacheFor(identityId, orgId);
});

events.on('assignment.revoked', async (event) => {
  const { identityId, orgId } = event.payload;
  await gatedhouse.invalidateCacheFor(identityId, orgId);
});

// Handle membership changes (from Citadel)
events.on('membership.updated', async (event) => {
  const { id, identityId, orgId, status, groups } = event.payload;
  await membershipCache.upsert({ id, identityId, orgId, status, groups });
});

events.on('membership.suspended', async (event) => {
  const { identityId, orgId } = event.payload;
  await membershipCache.updateStatus(identityId, orgId, 'suspended');
  await gatedhouse.invalidateCacheFor(identityId, orgId);
});

// Handle delegation changes (from Sphinx)
events.on('delegation.created', async (event) => {
  const delegation = event.payload;
  await delegationCache.upsert(delegation);
});

events.on('delegation.revoked', async (event) => {
  const { id } = event.payload;
  await delegationCache.delete(id);
});
```

**Step 9.2: Custom Event Adapter**

Integrate with your event bus (Kafka, RabbitMQ, Redis Pub/Sub):

**TypeScript:**
```typescript
import { EventAdapter } from '@gatedhouse/sdk';

class KafkaEventAdapter implements EventAdapter {
  async publish(eventType: string, payload: any): Promise<void> {
    await this.kafka.send({
      topic: 'gatedhouse.events',
      messages: [{ key: eventType, value: JSON.stringify(payload) }]
    });
  }

  async subscribe(eventType: string, handler: (payload: any) => Promise<void>): Promise<void> {
    await this.consumer.subscribe({ topic: 'gatedhouse.events' });
    this.consumer.on('message', async (msg) => {
      if (msg.key === eventType) {
        await handler(JSON.parse(msg.value));
      }
    });
  }
}

const gatedhouse = new Gatedhouse({
  ...config,
  events: {
    adapter: new KafkaEventAdapter(kafkaClient)
  }
});
```

---

### Phase 10: Admin API

**Step 10.1: Mount Admin Routes**

**TypeScript:**
```typescript
import express from 'express';
import { createAdminRouter } from '@gatedhouse/sdk';

const app = express();

// Admin routes for role/permission management
const adminRouter = createAdminRouter(gatedhouse, {
  requireAuth: true, // Require authentication
  requirePermission: 'admin:gatedhouse:*' // Admin-only
});

app.use('/api/admin/gatedhouse', adminRouter);
```

Available endpoints:

```
GET    /api/admin/gatedhouse/roles              # List all roles
POST   /api/admin/gatedhouse/roles              # Create role
GET    /api/admin/gatedhouse/roles/:key         # Get role details
PUT    /api/admin/gatedhouse/roles/:key         # Update role
DELETE /api/admin/gatedhouse/roles/:key         # Delete role

GET    /api/admin/gatedhouse/permissions        # List all permissions
POST   /api/admin/gatedhouse/permissions        # Create permission

GET    /api/admin/gatedhouse/assignments        # List assignments
POST   /api/admin/gatedhouse/assignments        # Create assignment
DELETE /api/admin/gatedhouse/assignments/:id    # Revoke assignment

GET    /api/admin/gatedhouse/delegations        # List delegations
POST   /api/admin/gatedhouse/delegations        # Create delegation
DELETE /api/admin/gatedhouse/delegations/:id    # Revoke delegation

GET    /api/admin/gatedhouse/memberships        # List memberships
GET    /api/admin/gatedhouse/memberships/:id    # Get membership details
```

**Python:**
```python
from fastapi import FastAPI
from gatedhouse.admin import create_admin_router

app = FastAPI()

admin_router = create_admin_router(
    gatedhouse,
    require_auth=True,
    require_permission="admin:gatedhouse:*"
)

app.include_router(admin_router, prefix="/api/admin/gatedhouse")
```

---

### Phase 11: Audit and Metrics

**Step 11.1: Configure Audit Logging**

**TypeScript:**
```typescript
import { AuditLogger } from '@gatedhouse/sdk';

const auditLogger = new AuditLogger({
  enabled: true,
  logDenials: true,      // Always log denials
  logSuccesses: false,   // Only in debug mode
  destination: 'stdout', // or custom handler
  format: 'json'
});

gatedhouse.setAuditLogger(auditLogger);

// Audit entries are automatically logged:
// {
//   "timestamp": "2026-02-13T10:30:00Z",
//   "eventType": "authorization.denied",
//   "identityId": "per_01HQXYZ...",
//   "orgId": "org_01HQXYZ...",
//   "permission": "workspace:projects:delete",
//   "resource": { "projectId": "proj_123" },
//   "reason": "missing_permission",
//   "metadata": { ... }
// }
```

**Step 11.2: Configure Metrics Collection**

**TypeScript:**
```typescript
import { MetricsCollector } from '@gatedhouse/sdk';

const metrics = new MetricsCollector({
  enabled: true,
  exportInterval: 60000 // Export every 60 seconds
});

gatedhouse.setMetricsCollector(metrics);

// Collected metrics:
// - gatedhouse_permission_checks_total (counter)
// - gatedhouse_permission_checks_denied (counter)
// - gatedhouse_delegation_checks_total (counter)
// - gatedhouse_delegation_invalid (counter)
// - gatedhouse_cache_hits (counter)
// - gatedhouse_cache_misses (counter)
// - gatedhouse_permission_check_duration_ms (histogram)

// Export to Prometheus, StatsD, etc.
metrics.on('export', (data) => {
  // Send to your metrics backend
});
```

---

### Phase 12: Testing

**Step 12.1: Run Conformance Tests**

Verify your SDK implementation against the shared test vectors:

**TypeScript:**
```bash
npm test -- --testPathPattern=conformance
```

**Python:**
```bash
pytest tests/conformance/
```

**Rust:**
```bash
cargo test --test conformance
```

**Step 12.2: Run Cross-Language Conformance Suite**

```bash
python tools/conformance_runner.py --all
```

This runs all test vectors across TypeScript, Python, and Rust SDKs, ensuring behavioral consistency.

**Step 12.3: Unit Tests**

**TypeScript:**
```typescript
import { matchPermission, hasPermission } from '@gatedhouse/sdk';

describe('Permission matching', () => {
  test('exact match', () => {
    expect(matchPermission('workspace:projects:read', 'workspace:projects:read')).toBe(true);
  });

  test('wildcard service', () => {
    expect(matchPermission('*:projects:read', 'workspace:projects:read')).toBe(true);
  });

  test('wildcard action', () => {
    expect(matchPermission('workspace:projects:*', 'workspace:projects:delete')).toBe(true);
  });

  test('full wildcard', () => {
    expect(matchPermission('*:*:*', 'anything:goes:here')).toBe(true);
  });

  test('no match', () => {
    expect(matchPermission('workspace:projects:read', 'workspace:projects:delete')).toBe(false);
  });
});
```

**Python:**
```python
from gatedhouse.core.permissions.matcher import match_permission

def test_permission_matching():
    assert match_permission("workspace:projects:read", "workspace:projects:read") == True
    assert match_permission("*:projects:read", "workspace:projects:read") == True
    assert match_permission("workspace:projects:*", "workspace:projects:delete") == True
    assert match_permission("*:*:*", "anything:goes:here") == True
    assert match_permission("workspace:projects:read", "workspace:projects:delete") == False
```

---

## Detailed Capabilities

### 1. Permission Matching

**Wildcard Support:**
- `*:*:*` → Matches everything (superuser)
- `workspace:*:*` → All actions on all workspace resources
- `workspace:projects:*` → All actions on projects
- `*:projects:read` → Read projects in any service
- `workspace:*:read` → Read any workspace resource

**Implementation Reference:**
- TypeScript: `sdk-typescript/src/permissions/matcher.ts`
- Python: `sdk-python/gatedhouse/core/permissions/matcher.py`
- Rust: `sdk-rust/src/permissions/matcher.rs`

**Functions:**
```typescript
matchPermission(granted: string, required: string): boolean
hasPermission(grantedSet: string[], required: string): boolean
hasAllPermissions(grantedSet: string[], required: string[]): boolean
hasAnyPermission(grantedSet: string[], required: string[]): boolean
expandWildcards(wildcards: string[], knownSet: string[]): string[]
intersectPermissions(setA: string[], setB: string[]): string[]
```

### 2. Role Resolution

**DAG Walking Algorithm:**
1. Start with directly assigned roles
2. Follow inheritance edges (`inherits` field)
3. Collect permissions from each visited role
4. Detect cycles (throw error if found)
5. Return deduplicated permission set

**Supported Patterns:**
- Single inheritance: `editor → viewer`
- Deep chains: `owner → admin → editor → viewer`
- Diamond patterns: `admin → [editor, manager] → viewer`
- Multiple inheritance: `superuser → [admin, developer]`

**Cycle Detection:**
```typescript
// This will throw an error:
await roleRepo.create({ key: 'a', inherits: ['b'] });
await roleRepo.create({ key: 'b', inherits: ['c'] });
await roleRepo.create({ key: 'c', inherits: ['a'] }); // ✗ Cycle!
```

**Implementation Reference:**
- TypeScript: `sdk-typescript/src/roles/resolver.ts`
- Python: `sdk-python/gatedhouse/core/roles/resolver.py`
- Rust: `sdk-rust/src/roles/resolver.rs`

### 3. Authorization Decision Engine

**Decision Algorithm:**

```typescript
async function checkPermission(
  ctx: GatedContext,
  required: string,
  resource?: any,
  policies?: string[]
): Promise<boolean> {
  // 1. Check suspension
  if (ctx.membership.status === 'suspended') {
    return false; // Always deny
  }

  // 2. Resolve effective permissions
  let effectivePermissions = ctx.permissions;

  // 3. Apply scopes (API keys, client credentials)
  if (ctx.scopes) {
    effectivePermissions = intersectPermissions(effectivePermissions, ctx.scopes);
  }

  // 4. Apply delegation constraints
  if (ctx.delegation) {
    const delegation = await delegationCache.get(ctx.delegation.id);

    // Check expiry
    if (delegation.expiresAt && new Date() > delegation.expiresAt) {
      return false;
    }

    // Check use limit
    if (delegation.usesRemaining !== null && delegation.usesRemaining <= 0) {
      return false;
    }

    // Three-way intersection
    const delegatorPerms = await getPermissions(delegation.delegatorId, ctx.org.id);
    const agentMaxPerms = delegation.constraints?.maxPermissions || ['*:*:*'];

    effectivePermissions = intersectPermissions(
      intersectPermissions(effectivePermissions, delegation.scopes),
      intersectPermissions(delegatorPerms, agentMaxPerms)
    );
  }

  // 5. Check permission
  if (!hasPermission(effectivePermissions, required)) {
    return false;
  }

  // 6. Evaluate custom policies
  if (policies && policies.length > 0) {
    for (const policy of policies) {
      const passed = await policyEngine.evaluate(policy, ctx, resource);
      if (!passed) {
        return false;
      }
    }
  }

  return true;
}
```

**Implementation Reference:**
- TypeScript: `sdk-typescript/src/permissions/checker.ts`
- Python: `sdk-python/gatedhouse/core/permissions/checker.py`
- Rust: `sdk-rust/src/permissions/checker.rs`

### 4. Caching Strategy

**Membership Cache:**
- Synced from Citadel (user management service)
- Stores: identity → org mappings, group memberships, ownership status
- Invalidated on: membership status change, group changes

**Delegation Cache:**
- Synced from Sphinx (delegation service)
- Stores: active delegations, scopes, constraints, expiry
- Invalidated on: delegation creation, revocation, expiry

**Resolved Permissions Cache:**
- Materialized view of identity → org → effective permissions
- Computed from: direct role assignments + group role assignments + role inheritance
- Invalidated on: role changes, assignment changes, role inheritance changes

**Cache Invalidation Events:**
```typescript
events.on('role.updated', () => invalidateCache('roles'));
events.on('assignment.created', (e) => invalidateCacheFor(e.identityId, e.orgId));
events.on('delegation.revoked', (e) => invalidateCache('delegations'));
```

### 5. Database Schema

**7 Tables:**

```sql
-- Role definitions
CREATE TABLE gatedhouse_roles (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    permissions TEXT[] NOT NULL,
    inherits TEXT[],
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Identity → Role assignments
CREATE TABLE gatedhouse_role_assignments (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    role_key TEXT REFERENCES gatedhouse_roles(key),
    assigned_by TEXT,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    UNIQUE(identity_id, org_id, role_key)
);

-- Group → Role assignments
CREATE TABLE gatedhouse_group_roles (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    role_key TEXT REFERENCES gatedhouse_roles(key),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(group_id, org_id, role_key)
);

-- Permission catalog
CREATE TABLE gatedhouse_permissions (
    permission TEXT PRIMARY KEY,
    service TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Membership cache (from Citadel)
CREATE TABLE gatedhouse_membership_cache (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    is_owner BOOLEAN DEFAULT FALSE,
    status TEXT NOT NULL,
    groups TEXT[],
    metadata JSONB,
    synced_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(identity_id, org_id)
);

-- Delegation cache (from Sphinx)
CREATE TABLE gatedhouse_delegation_cache (
    id TEXT PRIMARY KEY,
    delegator_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    constraints JSONB,
    expires_at TIMESTAMPTZ,
    uses_remaining INTEGER,
    metadata JSONB,
    synced_at TIMESTAMPTZ DEFAULT NOW()
);

-- Materialized permissions
CREATE TABLE gatedhouse_resolved_permissions (
    identity_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    permissions TEXT[] NOT NULL,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (identity_id, org_id)
);
```

**Indexes for Performance:**
```sql
CREATE INDEX idx_assignments_identity_org ON gatedhouse_role_assignments(identity_id, org_id);
CREATE INDEX idx_group_roles_group_org ON gatedhouse_group_roles(group_id, org_id);
CREATE INDEX idx_membership_identity_org ON gatedhouse_membership_cache(identity_id, org_id);
CREATE INDEX idx_delegation_agent_org ON gatedhouse_delegation_cache(agent_id, org_id);
CREATE INDEX idx_resolved_identity_org ON gatedhouse_resolved_permissions(identity_id, org_id);
```

---

## Common Use Cases

### Use Case 1: Multi-Tenant SaaS Application

**Scenario:** Workspace collaboration platform with orgs, projects, and documents.

**Roles:**
- `viewer`: Read-only access
- `editor`: Create and edit content
- `admin`: Manage team and settings
- `owner`: Full control (auto-assigned to org creator)

**Implementation:**

```typescript
// 1. Define roles
await roleRepo.create({
  key: 'viewer',
  permissions: ['workspace:*:read']
});

await roleRepo.create({
  key: 'editor',
  inherits: ['viewer'],
  permissions: ['workspace:projects:create', 'workspace:projects:update', 'workspace:documents:*']
});

await roleRepo.create({
  key: 'admin',
  inherits: ['editor'],
  permissions: ['workspace:*:delete', 'workspace:team:*']
});

await roleRepo.create({
  key: 'owner',
  inherits: ['admin'],
  permissions: ['*:*:*'],
  isSystem: true
});

// 2. Assign roles on user invitation
async function inviteUser(email: string, orgId: string, role: string) {
  const user = await createUser(email);
  const membership = await citadel.createMembership(user.id, orgId);

  // Sync to Gatedhouse
  await membershipCache.upsert({
    id: membership.id,
    identityId: user.id,
    orgId,
    entityType: 'user',
    status: 'pending', // Until they accept
    groups: []
  });

  // Assign role
  await assignment.assign({
    identityId: user.id,
    orgId,
    roleKey: role
  });
}

// 3. Check permission in request handler
app.delete('/api/projects/:id', async (req, res) => {
  const canDelete = await checker.check(
    req.gatedContext,
    'workspace:projects:delete',
    { projectId: req.params.id },
    ['resource.is_owner'] // Only owner can delete
  );

  if (!canDelete) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  await db.deleteProject(req.params.id);
  res.json({ success: true });
});
```

### Use Case 2: API Key with Scoped Access

**Scenario:** User creates API key with limited permissions for CI/CD.

**Implementation:**

```typescript
// 1. User creates API key with scopes
const apiKey = await apiKeyService.create({
  userId: 'per_01ALICE...',
  orgId: 'org_01HQXYZ...',
  name: 'CI/CD Deploy Key',
  scopes: [
    'workspace:projects:read',
    'workspace:projects:update',
    'workspace:deployments:*'
  ],
  expiresAt: new Date('2027-01-01')
});

// 2. JWT includes scopes
const token = jwt.sign({
  sub: 'per_01ALICE...',
  org: 'org_01HQXYZ...',
  scopes: apiKey.scopes,
  auth_method: 'api_key'
}, secret);

// 3. Authorization check
// User's role: admin → permissions: ['workspace:*:*', 'admin:*:*']
// API key scopes: ['workspace:projects:read', 'workspace:projects:update', 'workspace:deployments:*']

await checker.check(ctx, 'workspace:projects:read'); // ✓ Allowed
await checker.check(ctx, 'workspace:projects:update'); // ✓ Allowed
await checker.check(ctx, 'workspace:deployments:create'); // ✓ Allowed
await checker.check(ctx, 'workspace:documents:read'); // ✗ Denied (not in scopes)
await checker.check(ctx, 'admin:users:read'); // ✗ Denied (not in scopes)
```

### Use Case 3: Temporary Delegation for Vacation Coverage

**Scenario:** Alice delegates her admin permissions to Bob while on vacation.

**Implementation:**

```typescript
// 1. Alice creates delegation
const delegation = await sphinx.createDelegation({
  delegatorId: 'per_01ALICE...',
  agentId: 'per_01BOB...',
  orgId: 'org_01HQXYZ...',
  scopes: [
    'workspace:projects:*',
    'workspace:team:read',
    'workspace:team:update'
  ],
  constraints: {
    maxPermissions: ['workspace:*:*'], // Bob can't exceed workspace permissions
    resourceIds: null // No resource restriction
  },
  expiresAt: new Date('2026-03-01'), // 2 weeks
  usesRemaining: null // Unlimited uses
});

// 2. Sync to Gatedhouse
await delegationCache.upsert(delegation);

// 3. Bob authenticates (JWT includes delegation ID)
const bobToken = jwt.sign({
  sub: 'per_01BOB...',
  org: 'org_01HQXYZ...',
  delegation: delegation.id,
  auth_method: 'delegation'
}, secret);

// 4. Authorization check
// Alice's current permissions: ['workspace:*:*', 'admin:*:*']
// Bob's max permissions (from his roles): ['workspace:projects:*', 'workspace:docs:read']
// Delegation scopes: ['workspace:projects:*', 'workspace:team:read', 'workspace:team:update']

// Effective permissions = delegation scopes ∩ Bob's max ∩ Alice's current
// = ['workspace:projects:*', 'workspace:team:read', 'workspace:team:update'] ∩ ['workspace:projects:*', 'workspace:docs:read'] ∩ ['workspace:*:*', 'admin:*:*']
// = ['workspace:projects:*'] (only projects overlap)

await checker.check(bobCtx, 'workspace:projects:delete'); // ✓ Allowed
await checker.check(bobCtx, 'workspace:team:read'); // ✗ Denied (not in Bob's max)
await checker.check(bobCtx, 'admin:users:read'); // ✗ Denied (not in delegation scopes)
```

### Use Case 4: Group-Based Permissions

**Scenario:** Engineering and Sales teams have different permissions.

**Implementation:**

```typescript
// 1. Define groups in Citadel
const engineeringGroup = await citadel.createGroup({
  name: 'Engineering',
  orgId: 'org_01HQXYZ...'
});

const salesGroup = await citadel.createGroup({
  name: 'Sales',
  orgId: 'org_01HQXYZ...'
});

// 2. Assign roles to groups
await assignment.assignToGroup({
  groupId: engineeringGroup.id,
  orgId: 'org_01HQXYZ...',
  roleKey: 'developer' // Custom role with code access
});

await assignment.assignToGroup({
  groupId: salesGroup.id,
  orgId: 'org_01HQXYZ...',
  roleKey: 'sales_rep' // Custom role with CRM access
});

// 3. Add users to groups
await citadel.addUserToGroup('per_01ALICE...', engineeringGroup.id);
await citadel.addUserToGroup('per_01BOB...', salesGroup.id);

// 4. Sync membership to Gatedhouse
await membershipCache.upsert({
  identityId: 'per_01ALICE...',
  orgId: 'org_01HQXYZ...',
  groups: [engineeringGroup.id],
  status: 'active'
});

// 5. Permission resolution includes group roles
const alicePerms = await resolver.resolve('per_01ALICE...', 'org_01HQXYZ...');
// Returns permissions from:
// - Direct role assignments
// - + Group role assignments (engineering group)
```

### Use Case 5: Suspended User

**Scenario:** User's membership is suspended for policy violation.

**Implementation:**

```typescript
// 1. Suspend membership in Citadel
await citadel.suspendMembership('per_01ALICE...', 'org_01HQXYZ...');

// 2. Sync to Gatedhouse
await membershipCache.updateStatus('per_01ALICE...', 'org_01HQXYZ...', 'suspended');

// 3. All authorization checks fail
await checker.check(aliceCtx, 'workspace:projects:read'); // ✗ Denied (suspended)
await checker.check(aliceCtx, '*:*:*'); // ✗ Denied (even superuser denied)

// Reason: Suspension check happens BEFORE permission evaluation
```

---

## Best Practices

### 1. Permission Naming Conventions

**Use hierarchical structure:**
```
{service}:{resource}:{action}
```

**Examples:**
- ✓ `workspace:projects:create`
- ✓ `admin:users:delete`
- ✓ `billing:invoices:read`
- ✗ `create_project` (not hierarchical)
- ✗ `workspace-projects-create` (wrong separator)

**Action verbs:**
- `create`, `read`, `update`, `delete` (CRUD)
- `list`, `search`, `export`, `import`
- `approve`, `reject`, `publish`, `archive`

**Wildcard usage:**
- `workspace:*:read` → Read all workspace resources
- `workspace:projects:*` → All actions on projects
- Use sparingly; prefer explicit permissions

### 2. Role Design

**Keep roles focused:**
```typescript
// ✓ Good: Focused roles
viewer: ['workspace:*:read']
editor: ['workspace:projects:create', 'workspace:projects:update']
admin: ['workspace:*:*', 'admin:team:*']

// ✗ Bad: Kitchen-sink role
power_user: ['workspace:*:*', 'admin:*:read', 'billing:*:read', ...]
```

**Use inheritance for composition:**
```typescript
// ✓ Good: Composable hierarchy
viewer → editor → admin → owner

// ✗ Bad: Flat roles with duplication
viewer: ['workspace:*:read']
editor: ['workspace:*:read', 'workspace:projects:create', ...] // Duplicates viewer
```

**System roles:**
Mark system-managed roles as `isSystem: true`:
```typescript
await roleRepo.create({
  key: 'owner',
  isSystem: true, // Prevents manual assignment
  // ...
});
```

### 3. Performance Optimization

**Use materialized permissions:**
```typescript
// Precompute resolved permissions
await resolver.materialize('per_01ALICE...', 'org_01HQXYZ...');

// Fast lookup (O(1) instead of DAG walk)
const perms = await resolver.getMaterialized('per_01ALICE...', 'org_01HQXYZ...');
```

**Cache invalidation strategy:**
```typescript
// Invalidate only affected identities
events.on('role.updated', async (event) => {
  const affected = await db.getIdentitiesWithRole(event.roleKey);
  for (const identityId of affected) {
    await resolver.invalidate(identityId, event.orgId);
  }
});

// Batch invalidations
const toInvalidate = [...identityIds];
await resolver.invalidateBatch(toInvalidate, orgId);
```

**Connection pooling:**
```typescript
// Configure pool size based on load
database: {
  poolSize: process.env.NODE_ENV === 'production' ? 50 : 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
}
```

### 4. Security Best Practices

**Principle of least privilege:**
```typescript
// ✓ Good: Narrow scopes
apiKey.scopes = ['workspace:projects:read', 'workspace:projects:update'];

// ✗ Bad: Overly broad scopes
apiKey.scopes = ['*:*:*'];
```

**Time-bound delegations:**
```typescript
// ✓ Good: Limited duration
delegation.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

// ✗ Bad: Permanent delegation
delegation.expiresAt = null;
```

**Use limit enforcement:**
```typescript
// ✓ Good: Consumable delegation
delegation.usesRemaining = 100; // Auto-revokes after 100 uses

// Check remaining uses
if (delegation.usesRemaining <= 10) {
  await notifyUser('Delegation expiring soon');
}
```

**Audit critical operations:**
```typescript
auditLogger.logDenials = true; // Always log denials
auditLogger.logSuccesses = process.env.NODE_ENV === 'development'; // Only in dev
```

### 5. Error Handling

**Graceful degradation:**
```typescript
try {
  const canAccess = await checker.check(ctx, 'workspace:projects:read');
  if (!canAccess) {
    return res.status(403).json({ error: 'Forbidden' });
  }
} catch (error) {
  logger.error('Authorization check failed', { error, ctx });
  // Fail-safe: deny on error
  return res.status(500).json({ error: 'Internal server error' });
}
```

**Meaningful error messages:**
```typescript
// ✓ Good
if (!canDelete) {
  return res.status(403).json({
    error: 'Forbidden',
    message: 'You do not have permission to delete this project',
    required: 'workspace:projects:delete'
  });
}

// ✗ Bad
if (!canDelete) {
  return res.status(403).send('Forbidden');
}
```

### 6. Testing

**Test permission matching:**
```typescript
describe('Permission wildcards', () => {
  test('wildcard matches specific', () => {
    expect(matchPermission('workspace:*:read', 'workspace:projects:read')).toBe(true);
    expect(matchPermission('workspace:*:read', 'workspace:documents:read')).toBe(true);
    expect(matchPermission('workspace:*:read', 'workspace:projects:delete')).toBe(false);
  });
});
```

**Test role inheritance:**
```typescript
describe('Role resolution', () => {
  test('inherits permissions from parent roles', async () => {
    await roleRepo.create({ key: 'viewer', permissions: ['workspace:*:read'] });
    await roleRepo.create({ key: 'editor', inherits: ['viewer'], permissions: ['workspace:projects:update'] });

    const perms = await resolver.resolve('per_01USER...', 'org_01ORG...');
    expect(perms).toContain('workspace:*:read'); // From viewer
    expect(perms).toContain('workspace:projects:update'); // From editor
  });
});
```

**Test delegation:**
```typescript
describe('Delegation', () => {
  test('constrains permissions to delegation scopes', async () => {
    const ctx = {
      identity: { id: 'per_01BOB...' },
      permissions: ['workspace:*:*'], // Bob's max
      delegation: {
        scopes: ['workspace:projects:read'], // Limited delegation
        // ...
      }
    };

    expect(await checker.check(ctx, 'workspace:projects:read')).toBe(true);
    expect(await checker.check(ctx, 'workspace:projects:delete')).toBe(false);
  });
});
```

**Integration tests:**
```typescript
describe('Full authorization flow', () => {
  test('end-to-end permission check', async () => {
    // 1. Create user and org
    const user = await createUser();
    const org = await createOrg();

    // 2. Create membership
    const membership = await membershipCache.upsert({
      identityId: user.id,
      orgId: org.id,
      status: 'active',
      groups: []
    });

    // 3. Assign role
    await assignment.assign({
      identityId: user.id,
      orgId: org.id,
      roleKey: 'editor'
    });

    // 4. Resolve context
    const ctx = await gatedhouse.buildContext({
      identityId: user.id,
      orgId: org.id
    });

    // 5. Check permission
    expect(await checker.check(ctx, 'workspace:projects:create')).toBe(true);
  });
});
```

---

## Troubleshooting

### Issue: Permission check always returns false

**Symptoms:**
```typescript
const canCreate = await checker.check(ctx, 'workspace:projects:create');
// Always returns false
```

**Diagnosis:**
1. Check if membership is suspended:
   ```typescript
   console.log(ctx.membership.status); // Should be 'active'
   ```

2. Check if roles are assigned:
   ```typescript
   const assignments = await db.query('SELECT * FROM gatedhouse_role_assignments WHERE identity_id = $1', [ctx.identity.id]);
   console.log(assignments); // Should have rows
   ```

3. Check role permissions:
   ```typescript
   const role = await roleRepo.get('editor');
   console.log(role.permissions); // Should include required permission
   ```

4. Check permission resolution:
   ```typescript
   const perms = await resolver.resolve(ctx.identity.id, ctx.org.id);
   console.log(perms); // Should include required permission
   ```

5. Check scopes (if using API key):
   ```typescript
   console.log(ctx.scopes); // Should include required permission
   ```

**Solutions:**
- Ensure membership status is `active`, not `suspended` or `pending`
- Verify role assignment exists in database
- Check role definition includes required permission
- Re-materialize resolved permissions: `await resolver.materialize(identityId, orgId)`
- If using API key, ensure scopes include required permission

### Issue: Role inheritance not working

**Symptoms:**
```typescript
// editor inherits from viewer, but doesn't have viewer permissions
const perms = await resolver.resolve('per_01USER...', 'org_01ORG...');
console.log(perms); // Missing inherited permissions
```

**Diagnosis:**
1. Check role definition:
   ```typescript
   const editor = await roleRepo.get('editor');
   console.log(editor.inherits); // Should include ['viewer']
   ```

2. Check for cycles:
   ```typescript
   // This will throw if there's a cycle
   const perms = await resolver.resolve('per_01USER...', 'org_01ORG...');
   ```

3. Check parent role exists:
   ```typescript
   const viewer = await roleRepo.get('viewer');
   console.log(viewer); // Should exist
   ```

**Solutions:**
- Verify `inherits` field is correctly set
- Ensure parent role exists
- Check for inheritance cycles (A → B → A)
- Clear cache and re-materialize: `await resolver.invalidate(identityId, orgId); await resolver.materialize(identityId, orgId);`

### Issue: Delegation not applied

**Symptoms:**
```typescript
// User has delegation, but permissions not constrained
const ctx = { delegation: { id: 'del_01...' }, ... };
const canDelete = await checker.check(ctx, 'workspace:projects:delete');
// Returns true, but should be false
```

**Diagnosis:**
1. Check delegation cache:
   ```typescript
   const delegation = await delegationCache.get(ctx.delegation.id);
   console.log(delegation); // Should exist
   ```

2. Check expiry:
   ```typescript
   console.log(new Date() > delegation.expiresAt); // Should be false
   ```

3. Check uses remaining:
   ```typescript
   console.log(delegation.usesRemaining); // Should be > 0 or null
   ```

4. Check scopes:
   ```typescript
   console.log(delegation.scopes); // Should be constrained
   ```

**Solutions:**
- Ensure delegation exists in cache
- Check expiry hasn't passed
- Check uses remaining > 0
- Verify delegation scopes are constraining permissions
- Re-sync delegation from Sphinx

### Issue: Database migration fails

**Symptoms:**
```bash
npx tsx src/cli/migrate.ts up
# Error: relation "gatedhouse_roles" already exists
```

**Diagnosis:**
1. Check migration state:
   ```sql
   SELECT * FROM schema_migrations;
   ```

2. Check existing tables:
   ```sql
   SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'gatedhouse_%';
   ```

**Solutions:**
- If migration partially applied, manually rollback:
  ```bash
  npx tsx src/cli/migrate.ts down
  npx tsx src/cli/migrate.ts up
  ```

- If tables exist but migration tracking doesn't, manually mark as migrated:
  ```sql
  CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT NOW());
  INSERT INTO schema_migrations (version) VALUES ('001_initial_schema');
  ```

### Issue: JWKS verification fails

**Symptoms:**
```typescript
// JWT verification fails with "Invalid signature"
const identity = await jwtVerifier.verify(token);
// Throws error
```

**Diagnosis:**
1. Check JWKS URI:
   ```typescript
   console.log(config.jwt.jwksUri); // Should be accessible
   ```

2. Fetch JWKS manually:
   ```bash
   curl https://auth.example.com/.well-known/jwks.json
   ```

3. Check token header:
   ```typescript
   const decoded = jwt.decode(token, { complete: true });
   console.log(decoded.header.kid); // Key ID
   ```

4. Check JWKS cache:
   ```typescript
   const jwks = await jwksClient.getKeys();
   console.log(jwks); // Should include kid from token
   ```

**Solutions:**
- Verify JWKS URI is accessible
- Check network connectivity to auth server
- Clear JWKS cache: `await jwksClient.clearCache()`
- Ensure token `kid` matches a key in JWKS
- Check token `iss` and `aud` match configuration

### Issue: Performance degradation

**Symptoms:**
- Permission checks taking > 100ms
- Database CPU high
- Memory usage growing

**Diagnosis:**
1. Check query performance:
   ```sql
   EXPLAIN ANALYZE SELECT * FROM gatedhouse_resolved_permissions WHERE identity_id = 'per_01...' AND org_id = 'org_01...';
   ```

2. Check index usage:
   ```sql
   SELECT schemaname, tablename, indexname FROM pg_indexes WHERE tablename LIKE 'gatedhouse_%';
   ```

3. Check cache hit rate:
   ```typescript
   const stats = await gatedhouse.getStats();
   console.log(stats.cacheHitRate); // Should be > 90%
   ```

**Solutions:**
- Create missing indexes (see database schema section)
- Materialize resolved permissions: `await resolver.materializeAll()`
- Increase cache TTL in configuration
- Use connection pooling
- Batch permission checks:
  ```typescript
  const results = await Promise.all([
    checker.check(ctx, 'workspace:projects:read'),
    checker.check(ctx, 'workspace:projects:update'),
    checker.check(ctx, 'workspace:projects:delete')
  ]);
  ```

---

## Advanced Topics

### 1. Custom Permission Matching Logic

Override the default wildcard matching:

**TypeScript:**
```typescript
import { PermissionMatcher } from '@gatedhouse/sdk';

class CustomMatcher extends PermissionMatcher {
  match(granted: string, required: string): boolean {
    // Custom logic: support regex patterns
    if (granted.startsWith('regex:')) {
      const pattern = new RegExp(granted.slice(6));
      return pattern.test(required);
    }

    // Fall back to default wildcard matching
    return super.match(granted, required);
  }
}

const checker = new PermissionChecker(gatedhouse, policyEngine, new CustomMatcher());
```

### 2. Multi-Org Context

Handle users with access to multiple organizations:

**TypeScript:**
```typescript
async function buildMultiOrgContext(identityId: string): Promise<Map<string, GatedContext>> {
  const memberships = await membershipCache.getAllForIdentity(identityId);

  const contexts = new Map();
  for (const membership of memberships) {
    const ctx = await gatedhouse.buildContext({
      identityId,
      orgId: membership.orgId
    });
    contexts.set(membership.orgId, ctx);
  }

  return contexts;
}

// Usage
const contexts = await buildMultiOrgContext('per_01ALICE...');
const orgACtx = contexts.get('org_01A...');
const orgBCtx = contexts.get('org_01B...');

await checker.check(orgACtx, 'workspace:projects:create'); // Check in org A
await checker.check(orgBCtx, 'workspace:projects:create'); // Check in org B
```

### 3. Resource-Scoped Permissions

Implement fine-grained resource-level permissions:

**TypeScript:**
```typescript
// Permission format: {service}:{resource}:{resource_id}:{action}
registry.register('workspace:projects:proj_123:delete', {
  service: 'workspace',
  resource: 'projects',
  resourceId: 'proj_123',
  action: 'delete'
});

// Assign resource-specific permission
await assignment.assign({
  identityId: 'per_01ALICE...',
  orgId: 'org_01HQXYZ...',
  roleKey: 'project_123_owner' // Custom role for this project
});

// Check
await checker.check(ctx, 'workspace:projects:proj_123:delete'); // ✓
await checker.check(ctx, 'workspace:projects:proj_456:delete'); // ✗
```

### 4. Dynamic Role Assignment

Automatically assign roles based on identity attributes:

**TypeScript:**
```typescript
events.on('membership.created', async (event) => {
  const { identityId, orgId, metadata } = event.payload;

  // Auto-assign role based on email domain
  if (metadata.email.endsWith('@example.com')) {
    await assignment.assign({
      identityId,
      orgId,
      roleKey: 'employee'
    });
  }

  // Auto-assign role based on SSO group
  if (metadata.ssoGroups?.includes('Engineering')) {
    await assignment.assign({
      identityId,
      orgId,
      roleKey: 'developer'
    });
  }
});
```

### 5. Permission Analytics

Track permission usage for compliance and optimization:

**TypeScript:**
```typescript
const analytics = new PermissionAnalytics(gatedhouse);

// Track permission checks
analytics.on('check', (event) => {
  console.log({
    identityId: event.ctx.identity.id,
    permission: event.permission,
    allowed: event.result,
    timestamp: new Date()
  });
});

// Analyze usage
const report = await analytics.generateReport({
  orgId: 'org_01HQXYZ...',
  startDate: new Date('2026-01-01'),
  endDate: new Date('2026-01-31')
});

console.log(report);
// {
//   totalChecks: 15000,
//   denials: 250,
//   topPermissions: [
//     { permission: 'workspace:projects:read', count: 5000 },
//     { permission: 'workspace:projects:update', count: 2000 },
//     ...
//   ],
//   topDenials: [
//     { permission: 'admin:users:delete', count: 100 },
//     ...
//   ]
// }
```

### 6. Cross-Service Authorization

Coordinate authorization across multiple services:

**TypeScript:**
```typescript
// Service A: Workspace API
const workspaceGH = new Gatedhouse({
  ...config,
  events: {
    adapter: new KafkaAdapter('gatedhouse.events')
  }
});

// Service B: Admin API
const adminGH = new Gatedhouse({
  ...config,
  events: {
    adapter: new KafkaAdapter('gatedhouse.events') // Same event bus
  }
});

// Role update in Service A propagates to Service B
await workspaceGH.roleRepo.update('editor', { permissions: [...] });
// Event published to Kafka
// Service B receives event and invalidates cache
```

### 7. Dry-Run Mode

Test authorization changes without applying them:

**TypeScript:**
```typescript
const dryRun = new DryRunChecker(gatedhouse);

// Simulate role change
const impact = await dryRun.simulateRoleUpdate('editor', {
  permissions: ['workspace:projects:*'] // Add delete permission
});

console.log(impact);
// {
//   affectedUsers: 50,
//   newPermissions: ['workspace:projects:delete'],
//   removedPermissions: [],
//   warnings: ['This grants delete permission to 50 users']
// }

// Simulate assignment
const impact2 = await dryRun.simulateAssignment({
  identityId: 'per_01ALICE...',
  roleKey: 'admin'
});

console.log(impact2);
// {
//   currentPermissions: ['workspace:*:read', 'workspace:projects:update'],
//   newPermissions: ['workspace:*:*', 'admin:*:*'],
//   addedPermissions: ['workspace:*:delete', 'admin:*:*']
// }
```

---

## Conformance Testing

### Running Conformance Tests

All SDKs must pass the shared conformance test suite in `spec/test-vectors/`.

**Run all tests:**
```bash
python tools/conformance_runner.py --all
```

**Run specific SDK:**
```bash
python tools/conformance_runner.py --sdk typescript
python tools/conformance_runner.py --sdk python
python tools/conformance_runner.py --sdk rust
```

**Run specific test suite:**
```bash
python tools/conformance_runner.py --suite permission_matching
python tools/conformance_runner.py --suite role_dag_resolution
```

### Test Vector Format

Test vectors are JSON files with input/output pairs:

**Example: `spec/test-vectors/permission_matching.json`**
```json
{
  "name": "Permission Matching",
  "version": "1.0.0",
  "tests": [
    {
      "description": "Exact match",
      "input": {
        "granted": "workspace:projects:read",
        "required": "workspace:projects:read"
      },
      "expected": true
    },
    {
      "description": "Wildcard service",
      "input": {
        "granted": "*:projects:read",
        "required": "workspace:projects:read"
      },
      "expected": true
    },
    {
      "description": "No match",
      "input": {
        "granted": "workspace:projects:read",
        "required": "workspace:projects:delete"
      },
      "expected": false
    }
  ]
}
```

### Implementing Conformance Harness

Each SDK exposes a CLI tool that:
1. Reads test vectors from stdin
2. Executes tests
3. Returns results to stdout

**TypeScript:**
```typescript
// src/conformance.ts
import { matchPermission } from './permissions/matcher';

async function runConformanceTests() {
  const input = await readStdin();
  const tests = JSON.parse(input);

  const results = tests.tests.map(test => {
    const actual = matchPermission(test.input.granted, test.input.required);
    return {
      description: test.description,
      passed: actual === test.expected,
      expected: test.expected,
      actual
    };
  });

  console.log(JSON.stringify(results, null, 2));
}

runConformanceTests();
```

**Usage:**
```bash
cat spec/test-vectors/permission_matching.json | npx tsx src/conformance.ts
```

---

## Summary

This skills guide provides a comprehensive reference for using the Gatedhouse library to build authorization into applications. Key takeaways:

1. **Start with database setup** → Migrations create 7 tables
2. **Define roles and permissions** → Use hierarchical permission model
3. **Integrate with your framework** → Middleware for Express, FastAPI, Django, Axum
4. **Sync caches** → Membership from Citadel, delegation from Sphinx
5. **Check permissions** → Standard RBAC, scoped access, delegated authority
6. **Use custom policies** → Extend beyond role-based checks
7. **Monitor and audit** → Track denials, measure performance
8. **Test thoroughly** → Conformance tests ensure behavioral consistency

For more details, see:
- `README.md`: High-level overview
- `MULTI_LANGUAGE_STRATEGY.md`: Architecture decisions
- `spec/`: Shared specification (JSON schemas, SQL, test vectors)
- `sdk-typescript/`, `sdk-python/`, `sdk-rust/`: Language-specific implementations

---

**Version:** 1.0.0
**Last Updated:** 2026-02-13
**Maintained by:** Gatedhouse Team
