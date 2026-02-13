//! Gatedhouse Rust Conformance Harness
//!
//! Reads test vector suites from stdin (JSON), executes them against
//! the local implementation, and writes results to stdout.
//!
//! Used by tools/conformance_runner.py

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Re-use library code
use gatedhouse::permissions::matcher::{
    has_all_permissions, has_any_permission, has_permission, intersect_permissions, match_permission,
};
use gatedhouse::permissions::checker::PermissionChecker;
use gatedhouse::types::{
    AuthMethod, DelegationContext, EntityType, GatedContext, Identity, IdentityType,
    MembershipContext, OrgContext,
};

#[derive(Debug, Deserialize)]
struct TestSuite {
    suite: String,
    cases: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct Results {
    passed: u32,
    failed: u32,
    errors: Vec<String>,
}

fn make_minimal_context(overrides: &Value) -> GatedContext {
    let membership_status = overrides
        .get("membership_status")
        .and_then(|v| v.as_str())
        .unwrap_or("active");

    let permissions: Vec<String> = overrides
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let scopes: Option<Vec<String>> = overrides.get("scopes").and_then(|v| {
        if v.is_null() {
            None
        } else {
            v.as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        }
    });

    let delegation = overrides.get("delegation").and_then(|v| {
        if v.is_null() {
            return None;
        }

        let offset_seconds = v.get("expires_at_offset_seconds")?.as_i64()?;
        let expires_at = (Utc::now() + Duration::seconds(offset_seconds)).to_rfc3339();

        let uses_remaining = v.get("uses_remaining").and_then(|u| {
            if u.is_null() {
                None
            } else {
                u.as_i64()
            }
        });

        Some(DelegationContext {
            id: v.get("id").and_then(|v| v.as_str()).unwrap_or("dlg_test").to_string(),
            delegator_id: "per_test".to_string(),
            delegator_membership_id: "mbr_test".to_string(),
            scopes: v
                .get("scopes")
                .and_then(|s| s.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            constraints: HashMap::new(),
            expires_at,
            uses_remaining,
        })
    });

    GatedContext {
        identity: Identity {
            id: "per_test".to_string(),
            identity_type: IdentityType::Human,
            auth_method: AuthMethod::Password,
            email: None,
            name: None,
            mfa_verified: None,
        },
        org: OrgContext {
            id: "org_test".to_string(),
        },
        membership: MembershipContext {
            id: "mbr_test".to_string(),
            entity_type: EntityType::Person,
            is_owner: false,
            status: membership_status.to_string(),
            groups: vec![],
        },
        roles: vec![],
        permissions,
        scopes,
        delegation,
    }
}

fn run_permission_matching(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };
    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let granted = tc["granted"].as_str().unwrap_or("");
        let required = tc["required"].as_str().unwrap_or("");
        let expected = tc["expected"].as_bool().unwrap_or(false);

        let actual = match_permission(granted, required);
        if actual == expected {
            results.passed += 1;
        } else {
            results.failed += 1;
            results.errors.push(format!(
                "permission_matching/{}: expected {}, got {}",
                name, expected, actual
            ));
        }
    }
    results
}

fn run_has_permission(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };
    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let granted_set: Vec<String> = tc["granted_set"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let required = tc["required"].as_str().unwrap_or("");
        let expected = tc["expected"].as_bool().unwrap_or(false);

        let actual = has_permission(&granted_set, required);
        if actual == expected {
            results.passed += 1;
        } else {
            results.failed += 1;
            results.errors.push(format!(
                "has_permission/{}: expected {}, got {}",
                name, expected, actual
            ));
        }
    }
    results
}

fn run_has_all_permissions(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };
    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let granted_set: Vec<String> = tc["granted_set"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let required: Vec<String> = tc["required"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let expected = tc["expected"].as_bool().unwrap_or(false);

        let actual = has_all_permissions(&granted_set, &required);
        if actual == expected {
            results.passed += 1;
        } else {
            results.failed += 1;
            results.errors.push(format!(
                "has_all_permissions/{}: expected {}, got {}",
                name, expected, actual
            ));
        }
    }
    results
}

fn run_has_any_permissions(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };
    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let granted_set: Vec<String> = tc["granted_set"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let required: Vec<String> = tc["required"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let expected = tc["expected"].as_bool().unwrap_or(false);

        let actual = has_any_permission(&granted_set, &required);
        if actual == expected {
            results.passed += 1;
        } else {
            results.failed += 1;
            results.errors.push(format!(
                "has_any_permissions/{}: expected {}, got {}",
                name, expected, actual
            ));
        }
    }
    results
}

fn run_intersect_permissions(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };
    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let set_a: Vec<String> = tc["set_a"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let set_b: Vec<String> = tc["set_b"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let actual = intersect_permissions(&set_a, &set_b);
        let actual_set: HashSet<&str> = actual.iter().map(|s| s.as_str()).collect();
        let mut pass = true;

        if let Some(expected_contains) = tc.get("expected_contains").and_then(|v| v.as_array()) {
            for expected in expected_contains {
                if let Some(exp) = expected.as_str() {
                    if !actual_set.contains(exp) {
                        pass = false;
                        results.errors.push(format!(
                            "intersect_permissions/{}: expected to contain '{}', got [{}]",
                            name,
                            exp,
                            actual.join(", ")
                        ));
                    }
                }
            }
        }

        if let Some(expected_not_contains) = tc.get("expected_not_contains").and_then(|v| v.as_array()) {
            for not_expected in expected_not_contains {
                if let Some(ne) = not_expected.as_str() {
                    if actual_set.contains(ne) {
                        pass = false;
                        results.errors.push(format!(
                            "intersect_permissions/{}: expected NOT to contain '{}', got [{}]",
                            name,
                            ne,
                            actual.join(", ")
                        ));
                    }
                }
            }
        }

        if pass {
            results.passed += 1;
        } else {
            results.failed += 1;
        }
    }
    results
}

fn run_permission_check(cases: &[Value]) -> Results {
    let checker = PermissionChecker::new();
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };

    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let ctx = make_minimal_context(&tc["context"]);
        let required = tc["required"].as_str().unwrap_or("");
        let expected_allowed = tc["expected_allowed"].as_bool().unwrap_or(false);

        let result = checker.check(&ctx, required);
        if result.allowed == expected_allowed {
            results.passed += 1;
        } else {
            results.failed += 1;
            results.errors.push(format!(
                "permission_check/{}: expected allowed={}, got {}",
                name, expected_allowed, result.allowed
            ));
        }
    }
    results
}

fn run_role_dag_resolution(cases: &[Value]) -> Results {
    let mut results = Results { passed: 0, failed: 0, errors: vec![] };

    for tc in cases {
        let name = tc["name"].as_str().unwrap_or("unknown");
        let roles = tc["roles"].as_object().unwrap();
        let assigned_roles: Vec<&str> = tc["assigned_roles"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let mut permission_set: HashSet<String> = HashSet::new();
        let mut visited: HashSet<String> = HashSet::new();

        fn collect_permissions(
            role_id: &str,
            roles: &serde_json::Map<String, Value>,
            permission_set: &mut HashSet<String>,
            visited: &mut HashSet<String>,
        ) {
            if visited.contains(role_id) {
                return;
            }
            visited.insert(role_id.to_string());

            if let Some(role) = roles.get(role_id) {
                if let Some(perms) = role.get("permissions").and_then(|v| v.as_array()) {
                    for perm in perms {
                        if let Some(p) = perm.as_str() {
                            permission_set.insert(p.to_string());
                        }
                    }
                }
                if let Some(inherits) = role.get("inherits").and_then(|v| v.as_array()) {
                    for parent in inherits {
                        if let Some(p) = parent.as_str() {
                            collect_permissions(p, roles, permission_set, visited);
                        }
                    }
                }
            }
        }

        for role_id in &assigned_roles {
            collect_permissions(role_id, roles, &mut permission_set, &mut visited);
        }

        let expected_permissions: HashSet<String> = tc["expected_permissions"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        if permission_set == expected_permissions {
            results.passed += 1;
        } else {
            results.failed += 1;
            let mut actual: Vec<_> = permission_set.into_iter().collect();
            actual.sort();
            let mut expected: Vec<_> = expected_permissions.into_iter().collect();
            expected.sort();
            results.errors.push(format!(
                "role_dag_resolution/{}: expected [{}], got [{}]",
                name,
                expected.join(", "),
                actual.join(", ")
            ));
        }
    }
    results
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let suites: Vec<TestSuite> = serde_json::from_str(&input).unwrap();
    let mut totals = Results { passed: 0, failed: 0, errors: vec![] };

    for suite in &suites {
        let result = match suite.suite.as_str() {
            "permission_matching" => run_permission_matching(&suite.cases),
            "has_permission" => run_has_permission(&suite.cases),
            "has_all_permissions" => run_has_all_permissions(&suite.cases),
            "has_any_permissions" => run_has_any_permissions(&suite.cases),
            "intersect_permissions" => run_intersect_permissions(&suite.cases),
            "permission_check" => run_permission_check(&suite.cases),
            "role_dag_resolution" => run_role_dag_resolution(&suite.cases),
            _ => {
                totals.errors.push(format!("Unknown suite: {}", suite.suite));
                continue;
            }
        };
        totals.passed += result.passed;
        totals.failed += result.failed;
        totals.errors.extend(result.errors);
    }

    print!("{}", serde_json::to_string(&totals).unwrap());
}
