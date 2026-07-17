// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Enumerated value types shared with the Postgres schema.

use std::fmt;

/// Mirrors the `gatedhouse.entity_type` Postgres enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    User,
    Agent,
}

impl EntityType {
    pub fn db_value(&self) -> &'static str {
        match self {
            EntityType::User => "user",
            EntityType::Agent => "agent",
        }
    }

    pub fn from_db_value(value: &str) -> Result<Self, UnknownEnumValue> {
        match value {
            "user" => Ok(EntityType::User),
            "agent" => Ok(EntityType::Agent),
            other => Err(UnknownEnumValue {
                kind: "entity_type",
                value: other.to_string(),
            }),
        }
    }
}

/// Mirrors the `gatedhouse.membership_status` Postgres enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MembershipStatus {
    Active,
    Suspended,
    Pending,
}

impl MembershipStatus {
    pub fn db_value(&self) -> &'static str {
        match self {
            MembershipStatus::Active => "active",
            MembershipStatus::Suspended => "suspended",
            MembershipStatus::Pending => "pending",
        }
    }

    pub fn from_db_value(value: &str) -> Result<Self, UnknownEnumValue> {
        match value {
            "active" => Ok(MembershipStatus::Active),
            "suspended" => Ok(MembershipStatus::Suspended),
            "pending" => Ok(MembershipStatus::Pending),
            other => Err(UnknownEnumValue {
                kind: "membership_status",
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub struct UnknownEnumValue {
    pub kind: &'static str,
    pub value: String,
}

impl fmt::Display for UnknownEnumValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown {} value: {:?}", self.kind, self.value)
    }
}

impl std::error::Error for UnknownEnumValue {}
