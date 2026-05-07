//! Pluggable cache for the per-identity effective-permission set.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::{EffectivePermission, PermissionCacheKey};

/// Sits in front of the recursive-CTE permission-resolution query.
///
/// The library ships an [`InMemoryPermissionCache`] default. Hosts that
/// need a shared cache (Redis, Memcached, etc.) implement this trait
/// against their cache client and pass it to
/// `GatedhouseConfigBuilder::permission_cache(...)`.
///
/// Implementations must be `Send + Sync` and safe for concurrent use.
pub trait PermissionCache: Send + Sync {
    /// Return the cached list for `(identity_id, org_id)`, or `None` on
    /// miss / expiry.
    fn get(&self, identity_id: &str, org_id: &str) -> Option<Vec<EffectivePermission>>;

    /// Cache the effective-permission list. Implementations should
    /// treat the supplied vec as immutable (clone if needed).
    fn put(&self, identity_id: &str, org_id: &str, permissions: Vec<EffectivePermission>);

    /// Drop the cache entry for one identity in one org.
    fn invalidate(&self, identity_id: &str, org_id: &str);

    /// Drop every cached entry.
    fn invalidate_all(&self);
}

/// Default [`PermissionCache`]: thread-safe, in-process, TTL-expiring
/// `HashMap`. Lazy eviction on read.
///
/// Exposes counters for hits, misses, puts, and invalidations as
/// runtime observability — and to let tests prove caching behaviour,
/// not just outcomes.
pub struct InMemoryPermissionCache {
    ttl: Duration,
    entries: Mutex<HashMap<PermissionCacheKey, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    puts: AtomicU64,
    targeted_invalidations: AtomicU64,
    wholesale_invalidations: AtomicU64,
}

struct Entry {
    permissions: Vec<EffectivePermission>,
    expires_at: Instant,
}

impl InMemoryPermissionCache {
    /// Conservative default — covers brief bursts of activity for an
    /// identity while keeping the window for stale data after an
    /// out-of-band schema edit short.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

    pub fn new() -> Self {
        Self::with_ttl(Self::DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            puts: AtomicU64::new(0),
            targeted_invalidations: AtomicU64::new(0),
            wholesale_invalidations: AtomicU64::new(0),
        }
    }

    // ---- observability ----------------------------------------------------

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn put_count(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
    }

    pub fn targeted_invalidation_count(&self) -> u64 {
        self.targeted_invalidations.load(Ordering::Relaxed)
    }

    pub fn wholesale_invalidation_count(&self) -> u64 {
        self.wholesale_invalidations.load(Ordering::Relaxed)
    }

    pub fn size(&self) -> usize {
        self.entries.lock().expect("cache lock poisoned").len()
    }

    /// Reset all counters to zero. Does not touch cached entries.
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.puts.store(0, Ordering::Relaxed);
        self.targeted_invalidations.store(0, Ordering::Relaxed);
        self.wholesale_invalidations.store(0, Ordering::Relaxed);
    }
}

impl Default for InMemoryPermissionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionCache for InMemoryPermissionCache {
    fn get(&self, identity_id: &str, org_id: &str) -> Option<Vec<EffectivePermission>> {
        let key = PermissionCacheKey::new(identity_id, org_id);
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("cache lock poisoned");
        match entries.get(&key) {
            Some(entry) if entry.expires_at > now => {
                let result = entry.permissions.clone();
                drop(entries);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(result)
            }
            Some(_) => {
                entries.remove(&key);
                drop(entries);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                drop(entries);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn put(&self, identity_id: &str, org_id: &str, permissions: Vec<EffectivePermission>) {
        let key = PermissionCacheKey::new(identity_id, org_id);
        let entry = Entry {
            permissions,
            expires_at: Instant::now() + self.ttl,
        };
        self.entries
            .lock()
            .expect("cache lock poisoned")
            .insert(key, entry);
        self.puts.fetch_add(1, Ordering::Relaxed);
    }

    fn invalidate(&self, identity_id: &str, org_id: &str) {
        let key = PermissionCacheKey::new(identity_id, org_id);
        let removed = self
            .entries
            .lock()
            .expect("cache lock poisoned")
            .remove(&key)
            .is_some();
        if removed {
            self.targeted_invalidations.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn invalidate_all(&self) {
        self.entries
            .lock()
            .expect("cache lock poisoned")
            .clear();
        self.wholesale_invalidations
            .fetch_add(1, Ordering::Relaxed);
    }
}
