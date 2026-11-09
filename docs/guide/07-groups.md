# 7. Groups

Operations on `gh.groupManager()`. A group is identified by `(groupId, orgId)`;
`brokers` in `acme` and `brokers` in `beacon` are unrelated. Group roles are
set with `roleManager().assignToGroup` ([ch. 5](05-roles.md#assignments)).

| Operation | Behaviour |
|---|---|
| `createGroup(group, org, name, description)` | name and description optional; duplicate → `QUERY` error |
| `deleteGroup(group, org)` | deletes the group, its memberships and its roles; clears the cache |
| `hasGroup(group, org)`, `listGroups(org)` | |
| `addIdentityToGroup(group, org, id)` | group must exist; duplicate → `QUERY` error; effective only while the identity's membership is `ACTIVE` |
| `removeIdentityFromGroup(group, org, id)` | |
| `getGroupMembers(group, org)`, `getIdentityGroups(id, org)` | sorted IDs |

Removing an identity's membership removes it from all of the org's groups.

## Group sources

A `GroupSource` lets an external system (directory, HR system, event stream)
drive the group manager. Default: `LocalGroupSource` (no-op; the host calls
the group manager).

| Hook | Called |
|---|---|
| `start(gatedhouse)` | once by `create`, after the schema check; failure aborts `create` (Java/Python) |
| `close()` | when the instance closes; must be idempotent |

```java
public final class DirectoryGroupSource implements GroupSource {
    private Subscription subscription;

    @Override public void start(Gatedhouse gh) {
        subscription = directory.subscribe(e -> {
            switch (e.type()) {
                case MEMBER_ADDED -> gh.groupManager().addIdentityToGroup(e.groupId(), e.orgId(), e.identityId());
                case MEMBER_REMOVED -> gh.groupManager().removeIdentityFromGroup(e.groupId(), e.orgId(), e.identityId());
            }
        });
    }

    @Override public void close() {
        if (subscription != null) { subscription.cancel(); subscription = null; }
    }
}
// GatedhouseConfig.builder().database(db).groupSource(new DirectoryGroupSource()).build()
```

Python: subclass `GroupSource` with `start(self, gatedhouse)` and `close(self)`;
pass `GatedhouseConfig(group_source=...)`.

Rust: `start(&self, &dyn Gatedhouse)` receives a borrowed reference that
cannot be retained. Run long-lived listeners with the `Arc<dyn Gatedhouse>`
returned by `create` instead, and use `GroupSource` only for work that
completes inside `start`.

Handler requirements: idempotent (events may be redelivered; duplicates raise
`QUERY` errors), tolerant of ordering (adding to a group before the org
membership exists is allowed), thread-safe.
