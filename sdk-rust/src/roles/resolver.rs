//! Permission resolver — walks the role inheritance DAG and computes
//! the effective permission set for a membership.

use std::collections::HashSet;

use tracing::warn;

use crate::roles::repository::RoleRepositoryTrait;
use crate::roles::assignment::RoleAssignmentTrait;

/// Resolves effective permissions through role inheritance DAG.
pub struct PermissionResolver<R: RoleRepositoryTrait, A: RoleAssignmentTrait> {
    role_repo: R,
    assignments: A,
}

impl<R: RoleRepositoryTrait, A: RoleAssignmentTrait> PermissionResolver<R, A> {
    pub fn new(role_repo: R, assignments: A) -> Self {
        Self { role_repo, assignments }
    }

    /// Resolve all effective roles for a membership (direct + group).
    pub async fn resolve_roles(
        &self,
        membership_id: &str,
        _org_id: &str,
        groups: &[String],
    ) -> Vec<String> {
        let mut role_set = HashSet::new();

        if let Ok(direct) = self.assignments.get_role_ids(membership_id).await {
            for r in direct {
                role_set.insert(r);
            }
        }

        if let Ok(group_roles) = self.assignments.get_role_ids_for_groups(groups).await {
            for r in group_roles {
                role_set.insert(r);
            }
        }

        role_set.into_iter().collect()
    }

    /// Resolve all effective permissions by walking the role inheritance DAG.
    pub async fn resolve_permissions(
        &self,
        membership_id: &str,
        org_id: &str,
        groups: &[String],
    ) -> Vec<String> {
        let roles = self.resolve_roles(membership_id, org_id, groups).await;
        let mut permission_set = HashSet::new();
        let mut visited = HashSet::new();

        for role_id in &roles {
            self.collect_permissions(org_id, role_id, &mut permission_set, &mut visited).await;
        }

        permission_set.into_iter().collect()
    }

    async fn collect_permissions(
        &self,
        org_id: &str,
        role_id: &str,
        permission_set: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) {
        if visited.contains(role_id) {
            return; // Cycle detection
        }
        visited.insert(role_id.to_string());

        let role = match self.role_repo.resolve(org_id, role_id).await {
            Ok(Some(r)) => r,
            _ => {
                warn!(org_id, role_id, "Role not found during resolution");
                return;
            }
        };

        for perm in &role.permissions {
            permission_set.insert(perm.clone());
        }

        for parent in &role.inherits {
            Box::pin(self.collect_permissions(org_id, parent, permission_set, visited)).await;
        }
    }
}
