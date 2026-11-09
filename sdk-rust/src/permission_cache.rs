// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

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
/// `HashMap`, bounded to [`max_entries`](Self::max_entries) entries.
/// Expired entries are dropped when read, and swept whenever the cache
/// reaches its bound; if it is still full of live entries, the oldest tenth
/// is evicted. The bound matters because the org ID of a check often comes
/// from the request, so callers could otherwise grow the cache without limit.
///
/// Exposes counters for hits, misses, puts, and invalidations as
/// runtime observability — and to let tests prove caching behaviour,
/// not just outcomes.
pub struct InMemoryPermissionCache {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<PermissionCacheKey, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    puts: AtomicU64,
    targeted_invalidations: AtomicU64,
    wholesale_invalidations: AtomicU64,
    evictions: AtomicU64,
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

    /// Default bound on cached (identity, org) entries.
    pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

    pub fn new() -> Self {
        Self::with_ttl(Self::DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_ttl_and_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    /// # Panics
    /// If `max_entries` is zero.
    pub fn with_ttl_and_max_entries(ttl: Duration, max_entries: usize) -> Self {
        assert!(max_entries >= 1, "max_entries must be at least 1");
        Self {
            ttl,
            max_entries,
            entries: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            puts: AtomicU64::new(0),
            targeted_invalidations: AtomicU64::new(0),
            wholesale_invalidations: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Most (identity, org) entries held at once.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Entries removed to stay within [`max_entries`](Self::max_entries).
    pub fn eviction_count(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Drops expired entries; if still full, evicts the oldest tenth (all
    /// entries share one TTL, so the earliest expiry is the oldest entry).
    fn make_room(&self, entries: &mut HashMap<PermissionCacheKey, Entry>, now: Instant) {
        let before = entries.len();
        entries.retain(|_, e| e.expires_at > now);
        // Leave room for at least the incoming entry.
        let target = self.max_entries.saturating_sub((self.max_entries / 10).max(1));
        if entries.len() > target {
            let mut by_age: Vec<(Instant, PermissionCacheKey)> =
                entries.iter().map(|(k, e)| (e.expires_at, k.clone())).collect();
            by_age.sort_unstable_by_key(|(expires_at, _)| *expires_at);
            for (_, key) in by_age.into_iter().take(entries.len() - target) {
                entries.remove(&key);
            }
        }
        self.evictions
            .fetch_add((before - entries.len()) as u64, Ordering::Relaxed);
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
        self.evictions.store(0, Ordering::Relaxed);
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
        let now = Instant::now();
        let entry = Entry {
            permissions,
            expires_at: now + self.ttl,
        };
        let mut entries = self.entries.lock().expect("cache lock poisoned");
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            self.make_room(&mut entries, now);
        }
        entries.insert(key, entry);
        drop(entries);
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
