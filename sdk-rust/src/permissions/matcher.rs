//! Permission wildcard matching.
//!
//! Permissions follow the format: `{service}:{resource}:{action}`
//! Wildcards (`*`) can match any segment.
//!
//! Examples:
//! - `"files:documents:read"` matches `"files:documents:read"` (exact)
//! - `"files:*:read"` matches `"files:documents:read"` (resource wildcard)
//! - `"*:*:*"` matches everything (superadmin)

use std::collections::HashSet;

/// Check if a granted permission matches a required permission.
pub fn match_permission(granted: &str, required: &str) -> bool {
    if granted == required {
        return true;
    }

    let granted_parts: Vec<&str> = granted.split(':').collect();
    let required_parts: Vec<&str> = required.split(':').collect();

    // Both must be 3-segment format
    if granted_parts.len() != 3 || required_parts.len() != 3 {
        return granted == required;
    }

    for i in 0..3 {
        if granted_parts[i] == "*" {
            continue;
        }
        if granted_parts[i] != required_parts[i] {
            return false;
        }
    }

    true
}

/// Check if a set of granted permissions satisfies a required permission.
pub fn has_permission(granted_permissions: &[String], required: &str) -> bool {
    granted_permissions
        .iter()
        .any(|g| match_permission(g, required))
}

/// Check if a set of granted permissions satisfies all required permissions.
pub fn has_all_permissions(granted_permissions: &[String], required: &[String]) -> bool {
    required
        .iter()
        .all(|r| has_permission(granted_permissions, r))
}

/// Check if a set of granted permissions satisfies any of the required permissions.
pub fn has_any_permission(granted_permissions: &[String], required: &[String]) -> bool {
    required
        .iter()
        .any(|r| has_permission(granted_permissions, r))
}

/// Expand wildcard permissions against a set of known permissions.
pub fn expand_wildcards(wildcard_permissions: &[String], known_permissions: &[String]) -> Vec<String> {
    let mut expanded = HashSet::new();

    for granted in wildcard_permissions {
        if !granted.contains('*') {
            expanded.insert(granted.clone());
            continue;
        }
        for known in known_permissions {
            if match_permission(granted, known) {
                expanded.insert(known.clone());
            }
        }
        // Also keep the wildcard itself for runtime matching
        expanded.insert(granted.clone());
    }

    expanded.into_iter().collect()
}

/// Compute the intersection of two permission sets, respecting wildcards.
/// Used for delegation three-way intersection.
pub fn intersect_permissions(set_a: &[String], set_b: &[String]) -> Vec<String> {
    let mut result = Vec::new();

    for a in set_a {
        for b in set_b {
            if match_permission(a, b) {
                // b is more specific or equal — keep b
                result.push(b.clone());
            } else if match_permission(b, a) {
                // a is more specific — keep a
                result.push(a.clone());
            }
        }
    }

    // Deduplicate while preserving order
    let mut seen = HashSet::new();
    result.retain(|p| seen.insert(p.clone()));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(match_permission("files:documents:read", "files:documents:read"));
    }

    #[test]
    fn test_exact_mismatch() {
        assert!(!match_permission("files:documents:read", "files:documents:write"));
    }

    #[test]
    fn test_wildcard_action() {
        assert!(match_permission("files:documents:*", "files:documents:read"));
    }

    #[test]
    fn test_wildcard_resource() {
        assert!(match_permission("files:*:read", "files:documents:read"));
    }

    #[test]
    fn test_superadmin() {
        assert!(match_permission("*:*:*", "files:documents:read"));
    }

    #[test]
    fn test_wildcard_no_match() {
        assert!(!match_permission("files:*:write", "files:documents:read"));
    }

    #[test]
    fn test_non_standard_format() {
        assert!(match_permission("admin", "admin"));
        assert!(!match_permission("admin", "user"));
    }

    #[test]
    fn test_has_permission() {
        let perms = vec!["files:documents:read".into(), "files:documents:write".into()];
        assert!(has_permission(&perms, "files:documents:read"));
        assert!(!has_permission(&perms, "files:documents:delete"));
    }

    #[test]
    fn test_has_all_permissions() {
        let perms = vec!["*:*:*".into()];
        let required = vec!["files:documents:read".into(), "billing:invoices:write".into()];
        assert!(has_all_permissions(&perms, &required));
    }

    #[test]
    fn test_has_any_permission() {
        let perms = vec!["files:documents:read".into()];
        let required = vec!["files:documents:read".into(), "files:documents:write".into()];
        assert!(has_any_permission(&perms, &required));
    }

    #[test]
    fn test_intersect_exact_overlap() {
        let a = vec!["files:documents:read".into(), "files:documents:write".into()];
        let b = vec!["files:documents:write".into(), "billing:invoices:read".into()];
        let result = intersect_permissions(&a, &b);
        assert!(result.contains(&"files:documents:write".to_string()));
        assert!(!result.contains(&"files:documents:read".to_string()));
        assert!(!result.contains(&"billing:invoices:read".to_string()));
    }

    #[test]
    fn test_intersect_wildcard() {
        let a = vec!["files:*:*".into()];
        let b = vec!["files:documents:read".into(), "billing:invoices:read".into()];
        let result = intersect_permissions(&a, &b);
        assert!(result.contains(&"files:documents:read".to_string()));
        assert!(!result.contains(&"billing:invoices:read".to_string()));
    }

    #[test]
    fn test_intersect_disjoint() {
        let a = vec!["files:documents:read".into()];
        let b = vec!["billing:invoices:write".into()];
        let result = intersect_permissions(&a, &b);
        assert!(result.is_empty());
    }
}
