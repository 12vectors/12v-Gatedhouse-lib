// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Pluggable extension point for where group data originates.
//!
//! Mirrors the Java `GroupSource` interface. Both built-in and custom
//! implementations write to the same local `gatedhouse.groups` /
//! `gatedhouse.group_memberships` tables — the difference is *who*
//! triggers those writes.

use crate::gatedhouse::Gatedhouse;

/// Configured at factory time via
/// `GatedhouseConfigBuilder::group_source(...)`.
///
/// * [`LocalGroupSource`]: the host calls `gh.group_manager()` methods
///   directly. `start` is a no-op.
/// * Custom (e.g. a Citadel bridge): on `start`, register a listener
///   with the host's transport that translates incoming events into
///   `gh.group_manager()` write calls. Release the listener on `close`.
pub trait GroupSource: Send + Sync {
    /// Called once by `GatedhouseFactory::create` after the schema check
    /// passes and the `Gatedhouse` instance is fully constructed.
    fn start(&self, gatedhouse: &dyn Gatedhouse);

    /// Called when the `Gatedhouse` instance is dropped (or closed).
    /// Implementations should release listeners and any resources they
    /// hold. Must be idempotent.
    fn close(&self);
}

/// Default [`GroupSource`]. The host owns group lifecycle and calls
/// `gh.group_manager()` write methods directly. Holds no listeners and
/// no resources.
pub struct LocalGroupSource;

impl GroupSource for LocalGroupSource {
    fn start(&self, _gatedhouse: &dyn Gatedhouse) {
        // no-op
    }

    fn close(&self) {
        // no-op
    }
}
