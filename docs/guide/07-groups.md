# 7. Groups

A group is a team or title **inside one organization**, such as Acme's
`brokers` or Beacon's `admins`. A group holds roles; every member of the
group receives them. Groups are how you manage access for many people at
once, and how two orgs can give the same title different powers.

Group operations live on `gh.groupManager()` / `gh.group_manager()`; giving a
group roles is done through the [role manager](05-roles.md#assigning-roles-to-groups).

## Creating groups

A group is identified by its ID **together with** its org: `brokers` in
`acme` and `brokers` in `beacon` are unrelated groups.

```java
GroupManager groups = gh.groupManager();
groups.createGroup("brokers", "acme", "Brokers", "Licensed brokers");
groups.hasGroup("brokers", "acme");       // true
groups.listGroups("acme");                // ["brokers", ...], sorted
groups.deleteGroup("brokers", "acme");
```

```python
groups = gh.group_manager()
groups.create_group("brokers", "acme", "Brokers", "Licensed brokers")
groups.has_group("brokers", "acme")
groups.list_groups("acme")
groups.delete_group("brokers", "acme")
```

```rust
let groups = gh.group_manager();
groups.create_group("brokers", "acme", Some("Brokers"), Some("Licensed brokers"))?;
groups.has_group("brokers", "acme")?;
groups.list_groups("acme")?;
groups.delete_group("brokers", "acme")?;
```

Name and description are optional. Creating a group that already exists in
the org is an error. **Deleting a group removes its memberships and its
roles** in that org; its former members lose whatever they had only through
the group.

## Members

```java
groups.addIdentityToGroup("brokers", "acme", "alice");
groups.getGroupMembers("brokers", "acme");       // ["alice", ...]
groups.getIdentityGroups("alice", "acme");       // ["brokers", ...]
groups.removeIdentityFromGroup("brokers", "acme", "alice");
```

```python
groups.add_identity_to_group("brokers", "acme", "alice")
groups.get_group_members("brokers", "acme")
groups.get_identity_groups("alice", "acme")
groups.remove_identity_from_group("brokers", "acme", "alice")
```

```rust
groups.add_identity_to_group("brokers", "acme", "alice")?;
groups.get_group_members("brokers", "acme")?;
groups.get_identity_groups("alice", "acme")?;
groups.remove_identity_from_group("brokers", "acme", "alice")?;
```

- The group must exist; adding the same member twice is an error.
- Like role assignments, group membership doesn't require an org membership,
  but has no effect until the identity's membership is `ACTIVE`. Removing the
  identity from the org removes it from all of the org's groups.

## Giving a group its roles

```java
gh.roleManager().assignToGroup("brokers", "acme", "policy-viewer");
gh.roleManager().assignToGroup("brokers", "beacon", "policy-editor");   // same title, more power
```

Each member gets the group's roles, plus everything those roles inherit.

## When to use groups

Use a group whenever a second person might need the same access: it keeps
"who is on the brokers team?" answerable in one place, and one change updates
everyone. Use [direct assignments](05-roles.md#assigning-roles-to-identities)
for genuine one-person exceptions.

If your product has no notion of teams, you can skip groups entirely; the
group tables simply stay empty.

## Syncing groups from another system

Sometimes groups are owned elsewhere: an HR system, a directory, or a
separate identity service that publishes "member added" events. A
**group source** connects such a system to Gatedhouse. It doesn't change
where groups are stored; it decides *who calls* the group manager.

- **`LocalGroupSource`** (the default): your application calls the group
  manager itself. Nothing to configure.
- **A custom group source**: Gatedhouse calls `start` once the instance is
  ready, and `close` when the instance is closed. Your implementation
  subscribes to the external system in `start` and translates its events into
  group manager calls.

**Java**

```java
public final class DirectoryGroupSource implements GroupSource {
    private final DirectoryClient directory;
    private Subscription subscription;

    public DirectoryGroupSource(DirectoryClient directory) {
        this.directory = directory;
    }

    @Override
    public void start(Gatedhouse gh) {
        subscription = directory.subscribe(event -> {
            switch (event.type()) {
                case GROUP_CREATED  -> gh.groupManager().createGroup(
                    event.groupId(), event.orgId(), event.name(), null);
                case GROUP_DELETED  -> gh.groupManager().deleteGroup(event.groupId(), event.orgId());
                case MEMBER_ADDED   -> gh.groupManager().addIdentityToGroup(
                    event.groupId(), event.orgId(), event.identityId());
                case MEMBER_REMOVED -> gh.groupManager().removeIdentityFromGroup(
                    event.groupId(), event.orgId(), event.identityId());
            }
        });
    }

    @Override
    public void close() {                      // must be safe to call twice
        if (subscription != null) {
            subscription.cancel();
            subscription = null;
        }
    }
}

Gatedhouse gh = GatedhouseFactory.create(GatedhouseConfig.builder()
    .database(db)
    .groupSource(new DirectoryGroupSource(directoryClient))
    .build());
```

**Python**

```python
from gatedhouse import GroupSource

class DirectoryGroupSource(GroupSource):
    def __init__(self, directory):
        self._directory = directory
        self._subscription = None

    def start(self, gatedhouse):
        groups = gatedhouse.group_manager()
        self._subscription = self._directory.subscribe(
            on_member_added=lambda e: groups.add_identity_to_group(e.group_id, e.org_id, e.identity_id),
            on_member_removed=lambda e: groups.remove_identity_from_group(e.group_id, e.org_id, e.identity_id),
        )

    def close(self):
        if self._subscription is not None:
            self._subscription.cancel()
            self._subscription = None

gh = GatedhouseFactory.create(GatedhouseConfig(
    database=db, group_source=DirectoryGroupSource(directory_client)))
```

**Rust**

Rust's `GroupSource::start` receives a borrowed `&dyn Gatedhouse`, which an
event listener cannot keep. Until that changes, start long-running listeners
yourself with the `Arc` returned by `GatedhouseFactory::create`, and use
`GroupSource` only for setup that completes inside `start` and for cleanup in
`close`:

```rust
let gh = GatedhouseFactory::create(GatedhouseConfig::builder(db).build())?;
let listener_gh = gh.clone();                       // Arc<dyn Gatedhouse>
directory.subscribe(move |event| {
    let _ = listener_gh.group_manager()
        .add_identity_to_group(&event.group_id, &event.org_id, &event.identity_id);
});
```

Guidelines for any group source:

- **Make handlers idempotent.** Events can be redelivered; "already exists"
  errors on create and add can be ignored after checking with `hasGroup` /
  `getGroupMembers`, or by catching the error.
- **Events may arrive out of order.** A "member added" can arrive before the
  person's org membership exists; that is allowed, and the grant becomes
  effective once the membership is active.
- **`start` failures abort startup.** If `start` throws, `create` closes the
  source and fails with an initialization error.
- **Be thread-safe.** Handlers may run on any thread.
