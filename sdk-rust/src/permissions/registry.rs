//! Permission registry — tracks known permissions.

use std::collections::HashSet;
use std::sync::RwLock;

pub struct PermissionRegistry {
    permissions: RwLock<HashSet<String>>,
}

impl PermissionRegistry {
    pub fn new() -> Self {
        Self {
            permissions: RwLock::new(HashSet::new()),
        }
    }

    pub fn register(&self, permission: &str) {
        self.permissions.write().unwrap().insert(permission.to_string());
    }

    pub fn register_many(&self, permissions: &[String]) {
        let mut set = self.permissions.write().unwrap();
        for perm in permissions {
            set.insert(perm.clone());
        }
    }

    pub fn list(&self) -> Vec<String> {
        self.permissions.read().unwrap().iter().cloned().collect()
    }

    pub fn contains(&self, permission: &str) -> bool {
        self.permissions.read().unwrap().contains(permission)
    }
}

impl Default for PermissionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
