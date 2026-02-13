//! ABAC policy engine — register and evaluate custom policies.

use std::collections::HashMap;
use std::sync::RwLock;

use tracing::warn;

use crate::types::GatedContext;

/// A synchronous policy function.
pub type SyncPolicyFn = Box<dyn Fn(&GatedContext, &serde_json::Value) -> bool + Send + Sync>;

pub struct PolicyEngine {
    policies: RwLock<HashMap<String, SyncPolicyFn>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
        }
    }

    /// Register a synchronous policy function.
    pub fn register<F>(&self, name: &str, policy: F)
    where
        F: Fn(&GatedContext, &serde_json::Value) -> bool + Send + Sync + 'static,
    {
        self.policies
            .write()
            .unwrap()
            .insert(name.to_string(), Box::new(policy));
    }

    /// Evaluate a named policy. Returns false if policy not found (fail-closed).
    pub fn evaluate(
        &self,
        name: &str,
        ctx: &GatedContext,
        resource: &serde_json::Value,
    ) -> bool {
        let policies = self.policies.read().unwrap();
        match policies.get(name) {
            Some(policy) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| policy(ctx, resource))) {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(policy_name = name, "Policy evaluation panicked, denying");
                        false
                    }
                }
            }
            None => {
                warn!(policy_name = name, "Policy not found, denying");
                false
            }
        }
    }

    pub fn has_policy(&self, name: &str) -> bool {
        self.policies.read().unwrap().contains_key(name)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_ctx() -> GatedContext {
        GatedContext {
            identity: Identity {
                id: "per_test".into(),
                identity_type: IdentityType::Human,
                auth_method: AuthMethod::Password,
                email: None, name: None, mfa_verified: None,
            },
            org: OrgContext { id: "org_test".into() },
            membership: MembershipContext {
                id: "mbr_test".into(),
                entity_type: EntityType::Person,
                is_owner: false, status: "active".into(), groups: vec![],
            },
            roles: vec![], permissions: vec![], scopes: None, delegation: None,
        }
    }

    #[test]
    fn test_register_and_evaluate() {
        let engine = PolicyEngine::new();
        engine.register("is_owner", |ctx, _| ctx.membership.is_owner);
        assert!(!engine.evaluate("is_owner", &make_ctx(), &serde_json::Value::Null));
    }

    #[test]
    fn test_unknown_policy() {
        let engine = PolicyEngine::new();
        assert!(!engine.evaluate("nonexistent", &make_ctx(), &serde_json::Value::Null));
    }

    #[test]
    fn test_has_policy() {
        let engine = PolicyEngine::new();
        engine.register("exists", |_, _| true);
        assert!(engine.has_policy("exists"));
        assert!(!engine.has_policy("not_exists"));
    }
}
