# Gatedhouse Multi-Language SDK Strategy — Architecture Analysis

## 1. Problem Statement

We need to maintain Gatedhouse authorization libraries for **4 language ecosystems** (TypeScript, Python, Java, C#) from a **single repository**, ensuring:

- **Feature parity**: All SDKs implement the same authorization logic
- **Behavioral consistency**: Identical inputs produce identical outputs across all languages
- **Synchronized evolution**: Adding/removing features propagates to all SDKs
- **Idiomatic APIs**: Each SDK feels native to its ecosystem (Express middleware, Django middleware, Spring filters, ASP.NET middleware)
- **Manageable maintenance**: A small team can realistically maintain this

---

## 2. Anatomy of Gatedhouse — What Must Be Shared vs. What Can't

After analyzing the TypeScript implementation, the codebase splits into three distinct layers:

### Layer 1: Pure Authorization Logic (~300 lines, MUST be identical)

These are pure functions with zero I/O — they take data in, return decisions out:

| Function | Lines | Description |
|----------|-------|-------------|
| `matchPermission(granted, required)` | 15 | Wildcard segment matching (`files:*:read`) |
| `hasPermission(set, required)` | 3 | Set membership with wildcard matching |
| `hasAllPermissions(set, required[])` | 1 | All-of check |
| `hasAnyPermission(set, required[])` | 1 | Any-of check |
| `expandWildcards(wildcards, known)` | 15 | Wildcard expansion against known set |
| `intersectPermissions(setA, setB)` | 15 | Wildcard-aware set intersection |
| `check(ctx, permission)` → decision | 60 | Authorization decision (4 strategies) |
| `collectPermissions(role, visited)` | 20 | DAG walk with cycle detection |

**This is the kernel.** If these functions diverge across languages, authorization decisions will be inconsistent and we'll have a security problem.

### Layer 2: Database & Cache Operations (~1,200 lines, same SQL, different drivers)

| Component | Shared Element | Language-Specific |
|-----------|---------------|-------------------|
| Schema (7 tables) | SQL DDL is identical | Migration runner mechanics |
| Role repository | SQL queries identical | Driver binding (pg, psycopg, JDBC, Npgsql) |
| Role assignments | SQL queries identical | Driver binding |
| Membership cache | SQL queries identical | Driver binding |
| Delegation cache | SQL queries identical | Driver binding |
| Permission materialization | SQL queries identical | Transaction handling syntax |

**Key insight**: The SQL is the same everywhere. Only the database driver glue changes.

### Layer 3: Framework Integration (~1,500 lines, entirely language-specific)

| Component | TypeScript | Python | Java | C# |
|-----------|-----------|--------|------|----|
| HTTP middleware | Express | Django/FastAPI/Flask | Spring Filter/Interceptor | ASP.NET Middleware |
| JWT verification | jose | PyJWT/python-jose | nimbus-jose-jwt | Microsoft.IdentityModel |
| Logging | pino | logging/structlog | SLF4J/Logback | Microsoft.Extensions.Logging |
| Event bus | custom adapters | custom adapters | custom adapters | custom adapters |
| Admin API | Express Router | FastAPI/Django Router | Spring Controller | ASP.NET Controller |

**This layer cannot be shared.** It must be written idiomatically for each ecosystem.

---

## 3. Options Analysis

### Option A: Shared Specification + Idiomatic Implementations (Recommended)

**Approach**: Define the authorization contract once (schemas, algorithms, test cases) in a language-neutral specification layer. Each SDK implements the contract idiomatically but is validated against a shared conformance test suite.

```
gatedhouse/
├── spec/                          # Source of truth (language-neutral)
│   ├── schemas/
│   │   ├── gated_context.json     # JSON Schema for GatedContext
│   │   ├── role_definition.json   # JSON Schema for roles
│   │   ├── events.json            # Event type catalog
│   │   └── config.json            # Configuration schema
│   ├── sql/
│   │   ├── migrations/
│   │   │   └── 001_initial.sql    # Raw SQL (shared across all SDKs)
│   │   └── queries/
│   │       ├── roles.sql          # Named query templates
│   │       ├── assignments.sql
│   │       ├── membership.sql
│   │       └── delegation.sql
│   ├── test-vectors/              # Shared conformance tests
│   │   ├── permission_matching.json
│   │   ├── wildcard_expansion.json
│   │   ├── intersection.json
│   │   ├── delegation_check.json
│   │   ├── scoped_check.json
│   │   └── role_dag_resolution.json
│   └── codegen/                   # Python-based code generation
│       ├── generate.py            # Main generator
│       ├── templates/
│       │   ├── typescript/
│       │   ├── python/
│       │   ├── java/
│       │   └── csharp/
│       └── requirements.txt
│
├── sdk-typescript/                # TypeScript SDK (existing, refactored)
│   ├── package.json
│   ├── src/
│   └── tests/
│
├── sdk-python/                    # Python SDK
│   ├── pyproject.toml
│   ├── gatedhouse/
│   └── tests/
│
├── sdk-java/                      # Java SDK
│   ├── pom.xml
│   ├── src/main/java/
│   └── src/test/java/
│
├── sdk-csharp/                    # C# SDK
│   ├── Gatedhouse.csproj
│   ├── src/
│   └── tests/
│
└── tools/                         # Python tooling
    ├── conformance_runner.py      # Runs test vectors against all SDKs
    ├── schema_validator.py        # Validates schemas
    └── sync_checker.py            # Detects drift between SDKs
```

**What Python does here**:
- **Code generation**: Generates types/enums/constants from JSON Schema into all 4 languages
- **Conformance testing**: Loads test vectors, invokes each SDK's pure-function exports, compares results
- **Drift detection**: Compares public API surfaces across SDKs
- **SQL distribution**: Copies shared SQL into each SDK's migration format

**What gets generated from spec/**:
- Type definitions (GatedContext, RoleDefinition, etc.) → language-specific classes/interfaces
- Event type constants → language-specific enums
- SQL migrations → language-specific migration runners
- Permission/role/event constants → language-specific constants

**What gets manually implemented per SDK**:
- Core permission matching algorithms (idiomatic per language)
- Database driver integration
- HTTP framework middleware
- JWT verification
- Event bus adapters

**Conformance testing flow**:
```
spec/test-vectors/permission_matching.json:
[
  {
    "name": "exact_match",
    "granted": "files:documents:read",
    "required": "files:documents:read",
    "expected": true
  },
  {
    "name": "wildcard_resource",
    "granted": "files:*:read",
    "required": "files:documents:read",
    "expected": true
  },
  {
    "name": "three_way_delegation",
    "delegation_scopes": ["files:documents:write", "workflow:*:*"],
    "agent_permissions": ["files:*:*", "workflow:instances:*"],
    "delegator_permissions": ["files:documents:read", "files:documents:write"],
    "required": "files:documents:write",
    "expected": true
  }
  ...
]
```

Each SDK exposes a thin CLI or test harness that consumes these vectors:
```bash
# CI runs all four:
python tools/conformance_runner.py --sdk typescript
python tools/conformance_runner.py --sdk python
python tools/conformance_runner.py --sdk java
python tools/conformance_runner.py --sdk csharp
```

**Pros**:
- Each SDK is fully idiomatic (Pythonic Python, idiomatic Java, etc.)
- No FFI complexity, no native compilation, no WASM runtimes
- Shared test vectors guarantee behavioral consistency where it matters
- SQL is literally shared (copy, not reimplemented)
- Code generation eliminates the #1 source of drift (type definitions)
- Easy to onboard language-specific contributors
- Each SDK can be published to its native package registry independently
- Works with each language's standard toolchain (pip, maven, nuget, npm)

**Cons**:
- Core logic is reimplemented 4 times (but it's ~300 lines, well-specified)
- Must discipline team to update spec/ first, then propagate
- Conformance tests catch divergence after the fact, not at author time

**Risk mitigation**: The core logic is small (~300 lines), well-defined, and has 100+ test vectors. Reimplementing `matchPermission` in Python/Java/C# is trivial — the risk is in the edge cases, which the test vectors cover exhaustively.

---

### Option B: Rust Core + FFI Bindings

**Approach**: Write the pure authorization logic in Rust, expose it via FFI to all 4 languages.

```
gatedhouse/
├── core/                          # Rust crate
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── matcher.rs             # Permission matching
│   │   ├── checker.rs             # Authorization decisions
│   │   ├── resolver.rs            # DAG walking
│   │   └── ffi.rs                 # C-compatible FFI exports
│   └── tests/
│
├── bindings-typescript/           # NAPI-RS bindings
├── bindings-python/               # PyO3 bindings
├── bindings-java/                 # JNI bindings
├── bindings-csharp/               # P/Invoke bindings
│
├── sdk-typescript/                # TS SDK (uses native addon)
├── sdk-python/                    # Python SDK (uses .so/.dll)
├── sdk-java/                      # Java SDK (uses JNI)
└── sdk-csharp/                    # C# SDK (uses P/Invoke)
```

**What Rust does**: Permission matching, wildcard expansion, intersection, DAG walking, authorization decision logic. All pure functions, no I/O.

**What each SDK still does**: Database, middleware, JWT, events, admin API.

**Pros**:
- **Single implementation** of core logic — guaranteed consistency
- Rust is fast and memory-safe
- Well-established FFI story (PyO3, NAPI-RS, JNI, P/Invoke)
- If core logic grows complex (e.g., ReBAC, graph-based policies), single implementation is a major win

**Cons**:
- **Build complexity explodes**: Must cross-compile Rust for Linux/macOS/Windows × x86/ARM
- **Distribution pain**: Python wheels need manylinux builds, npm needs prebuild-install, Java needs JNI jar packaging, NuGet needs runtime-specific packages
- **Debugging is harder**: Stack traces cross FFI boundary, harder to diagnose issues
- **Contributor barrier**: Requires Rust knowledge to modify core logic
- **Overkill for ~300 lines**: The core logic is simple enough that reimplementation risk is low
- **CI/CD complexity**: Need Rust toolchain + cross-compilation in CI for all platforms
- **Impedance mismatch**: Passing GatedContext across FFI boundary requires serialization, negating some performance benefit

**Verdict**: Justified if core logic is complex/large (thousands of lines) or if correctness is life-critical. For ~300 lines of well-tested string matching and set operations, the overhead is hard to justify.

---

### Option C: WebAssembly Core

**Approach**: Compile core logic to WASM, run it in each language via WASM runtimes.

```
gatedhouse/
├── core/                          # Rust → WASM (or AssemblyScript)
│   ├── src/                       # Core logic compiled to .wasm
│   └── build/
│       └── gatedhouse_core.wasm
│
├── sdk-typescript/                # Uses wasm directly (browser + node)
├── sdk-python/                    # Uses wasmtime-py
├── sdk-java/                      # Uses wasmtime-java
└── sdk-csharp/                    # Uses wasmtime-dotnet
```

**Pros**:
- Single implementation, portable binary
- No cross-compilation per platform (WASM is platform-independent)
- Simpler than Rust FFI — standard WASM interface

**Cons**:
- **WASM runtimes add dependency**: wasmtime-py, wasmtime-java are non-trivial deps
- **Cold start overhead**: WASM module instantiation adds latency on first call
- **Data marshaling**: GatedContext must be serialized to pass across WASM boundary
- **Ecosystem maturity**: WASM-in-Java and WASM-in-C# are less mature than native
- **Same "overkill for ~300 lines" problem** as Rust FFI
- **Debugging is opaque**: WASM stack traces are not developer-friendly

**Verdict**: Interesting for complex computation engines. Overkill here. The marshaling cost of passing string arrays across WASM boundary may exceed the cost of the actual matching logic.

---

### Option D: Python Core + Embedded Interpreter

**Approach**: Write core logic in Python, embed a Python interpreter in each SDK.

**Immediately rejected**: Embedding CPython in Java/C#/Node.js is fragile, slow, and creates a massive deployment dependency. No production authorization library should require a Python runtime in a Java microservice.

---

### Option E: gRPC Sidecar / Microservice

**Approach**: Abandon the embedded library model. Run Gatedhouse as a sidecar or microservice. Each SDK is a thin gRPC/HTTP client.

```
gatedhouse/
├── server/                        # Single implementation (Python or Go)
│   ├── src/
│   └── Dockerfile
│
├── client-typescript/             # Thin gRPC/HTTP client
├── client-python/
├── client-java/
└── client-csharp/
```

**Pros**:
- **Single implementation** of everything (not just core logic)
- Thin clients are trivial to maintain (~200 lines each)
- Language of server can be whatever the team is strongest in
- Schema driven (protobuf/OpenAPI) guarantees client consistency

**Cons**:
- **Contradicts Gatedhouse's entire design philosophy**: The spec explicitly chose embedded over centralized to eliminate per-request network hops
- **Reintroduces the IAM bottleneck** the platform is designed to eliminate
- **Single point of failure** per service
- **Latency**: Even localhost gRPC adds ~1ms vs ~10μs for in-process
- **Deployment complexity**: Every service now needs a sidecar

**Verdict**: Architecturally wrong for Gatedhouse. The spec exists specifically to avoid this pattern.

---

## 4. Recommendation: Option A (Shared Specification + Idiomatic Implementations)

### Why

| Criterion | Option A (Spec) | Option B (Rust FFI) | Option C (WASM) | Option E (Service) |
|-----------|----------------|--------------------|-----------------|--------------------|
| Core logic consistency | Test vectors (high) | Single impl (highest) | Single impl (highest) | Single impl (highest) |
| Build complexity | Standard per-language | Cross-compile hell | WASM runtime deps | Docker + sidecar |
| Debugging | Native stack traces | FFI boundary issues | Opaque WASM traces | Network debugging |
| Contributor access | Any language dev | Requires Rust | Requires Rust/AS | Single language |
| Distribution | Standard registries | Platform-specific binaries | WASM + runtime | Docker image |
| Idiomatic APIs | Fully native | Native wrapper + FFI | Native wrapper + WASM | gRPC client |
| Maintenance cost | 4x core logic (small) | 4x bindings + Rust | 4x bindings + Rust | 1x server + 4x thin |
| Performance | Native | Native + FFI overhead | WASM overhead | Network overhead |
| Proportionality | Fits ~300 lines | Overkill | Overkill | Wrong architecture |

### The deciding factor

The core authorization logic is **~300 lines of pure string matching and set operations**. This is:
- Trivially correct to reimplement in any language
- Fully specifiable via test vectors (input → expected output)
- Not growing into complex graph algorithms (the spec is frozen for v1)

The real maintenance burden is in **Layer 3** (middleware, JWT, database drivers) which **cannot be shared regardless of approach** — it must be idiomatic per ecosystem. Option A acknowledges this reality and focuses effort on the right problem: ensuring the decision kernel is consistent via exhaustive testing.

If Gatedhouse later evolves into something with complex graph traversal (ReBAC) or ML-based policy evaluation, we should revisit Option B (Rust core). For RBAC/ABAC with wildcard matching, Option A is the proportionate choice.

---

## 5. Implementation Plan for Option A

### Phase 1: Extract Shared Specification

1. Create `spec/schemas/` with JSON Schema for all types (GatedContext, RoleDefinition, events, config)
2. Create `spec/sql/` with raw SQL migrations and parameterized query templates
3. Create `spec/test-vectors/` with exhaustive test cases extracted from current TS tests + new edge cases
4. Create `spec/codegen/` with Python generator for types, enums, constants

### Phase 2: Restructure TypeScript SDK

1. Move current implementation to `sdk-typescript/`
2. Replace hand-written types with generated types (from JSON Schema)
3. Replace hand-written event constants with generated enums
4. Add conformance test runner that loads `spec/test-vectors/`

### Phase 3: Build Python SDK

1. Python package in `sdk-python/` (pyproject.toml, src layout)
2. Core logic: permission matching, checker, resolver (idiomatic Python)
3. Database layer: asyncpg or psycopg3
4. Framework middleware: FastAPI and Django support
5. JWT verification: PyJWT
6. Conformance tests passing

### Phase 4: Build Java SDK

1. Maven/Gradle project in `sdk-java/`
2. Core logic in Java
3. Database: JDBC / HikariCP
4. Framework: Spring Boot auto-configuration
5. JWT: nimbus-jose-jwt
6. Conformance tests passing

### Phase 5: Build C# SDK

1. .NET project in `sdk-csharp/`
2. Core logic in C#
3. Database: Npgsql
4. Framework: ASP.NET Core middleware
5. JWT: Microsoft.IdentityModel.Tokens
6. Conformance tests passing

### Phase 6: CI/CD

1. Monorepo CI that runs all 4 SDK test suites
2. Conformance gate: PRs that touch `spec/` must pass all 4 SDKs
3. Drift detection: automated check that public API surfaces match
4. Independent publishing to npm, PyPI, Maven Central, NuGet

### Estimated Effort per SDK

| Component | TS (refactor) | Python | Java | C# |
|-----------|:---:|:---:|:---:|:---:|
| Core logic (matcher, checker, resolver) | 1d | 2d | 2d | 2d |
| Types (generated) | 0.5d | 0.5d | 0.5d | 0.5d |
| Database layer | 1d | 2d | 2d | 2d |
| Migrations | 0.5d | 1d | 1d | 1d |
| HTTP middleware | 0.5d | 2d | 2d | 2d |
| JWT verification | 0.5d | 1d | 1d | 1d |
| Event handling | 0.5d | 1d | 1d | 1d |
| Admin API | 0.5d | 1d | 1.5d | 1.5d |
| Conformance tests | 1d | 1d | 1d | 1d |
| **Total** | **~5d** | **~11d** | **~12d** | **~12d** |

---

## 6. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Core logic diverges across SDKs | Medium | High (security) | Exhaustive test vectors + CI conformance gate |
| SQL queries drift | Low | Medium | Shared SQL in spec/, templated into each SDK |
| Type definitions drift | Low | Low | Code-generated from JSON Schema |
| Event handler behavior diverges | Medium | High | Event handling test vectors with before/after DB state |
| Team lacks expertise in all 4 languages | High | Medium | Prioritize by platform adoption; build Python + Java first if demand exists |
| Monorepo tooling overhead | Medium | Low | Use Turborepo or custom Python orchestrator; each SDK builds independently |

---

## 7. Alternative: Start With 2, Not 4

A pragmatic path: **don't build all 4 SDKs immediately**. Build the spec layer and one additional SDK (likely Python, given team context), then add Java and C# when actual service teams need them. The spec layer ensures future SDKs can be added without retrofitting.

```
Phase 1: spec/ + sdk-typescript/ (refactor)     → Week 1-2
Phase 2: sdk-python/                             → Week 3-5
Phase 3: sdk-java/ (when needed)                 → Future
Phase 4: sdk-csharp/ (when needed)               → Future
```

The spec layer is the investment. Once it exists, adding a new language SDK is a bounded 2-week effort.
