// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Top-level configuration object.

use std::sync::Arc;

use crate::database::Database;
use crate::group_source::{GroupSource, LocalGroupSource};
use crate::permission_cache::PermissionCache;
use crate::token_verifier::TokenVerifierConfig;

/// Mirrors the Java `GatedhouseConfig`. Only `database` is required;
/// every other component has a sensible default. Permission caching is
/// opt-in: with no cache configured (the default), every permission
/// read goes straight to the database with zero cache overhead.
pub struct GatedhouseConfig {
    pub(crate) database: Arc<dyn Database>,
    pub(crate) group_source: Arc<dyn GroupSource>,
    pub(crate) permission_cache: Option<Arc<dyn PermissionCache>>,
    pub(crate) token_verifier: Option<TokenVerifierConfig>,
}

impl GatedhouseConfig {
    pub fn builder(database: Arc<dyn Database>) -> GatedhouseConfigBuilder {
        GatedhouseConfigBuilder {
            database,
            group_source: None,
            permission_cache: None,
            token_verifier: None,
        }
    }

    pub fn database(&self) -> &Arc<dyn Database> {
        &self.database
    }

    /// The configured permission cache, or `None` if the host did not
    /// opt in — in which case caching is disabled and every permission
    /// read goes to the database.
    pub fn permission_cache(&self) -> Option<&Arc<dyn PermissionCache>> {
        self.permission_cache.as_ref()
    }
}

pub struct GatedhouseConfigBuilder {
    database: Arc<dyn Database>,
    group_source: Option<Arc<dyn GroupSource>>,
    permission_cache: Option<Arc<dyn PermissionCache>>,
    token_verifier: Option<TokenVerifierConfig>,
}

impl GatedhouseConfigBuilder {
    /// Optional. Defaults to [`LocalGroupSource`] (host owns group
    /// writes via `gh.group_manager()`).
    pub fn group_source(mut self, group_source: Arc<dyn GroupSource>) -> Self {
        self.group_source = Some(group_source);
        self
    }

    /// Optional — caching is opt-in and disabled by default; when unset,
    /// every permission read goes straight to the database with zero
    /// cache overhead. Pass
    /// [`InMemoryPermissionCache`](crate::permission_cache::InMemoryPermissionCache)
    /// for a process-local cache (60-second TTL by default), or a custom
    /// implementation to back the cache with Redis, Memcached, or any
    /// other shared store.
    pub fn permission_cache(mut self, permission_cache: Arc<dyn PermissionCache>) -> Self {
        self.permission_cache = Some(permission_cache);
        self
    }

    /// Optional. When set, `Gatedhouse::verify_token` is enabled and
    /// configured against the supplied JWKS URI, issuer, and audience.
    /// When unset, `verify_token` returns an error.
    pub fn token_verifier(mut self, token_verifier: TokenVerifierConfig) -> Self {
        self.token_verifier = Some(token_verifier);
        self
    }

    pub fn build(self) -> GatedhouseConfig {
        GatedhouseConfig {
            database: self.database,
            group_source: self
                .group_source
                .unwrap_or_else(|| Arc::new(LocalGroupSource)),
            permission_cache: self.permission_cache,
            token_verifier: self.token_verifier,
        }
    }
}
