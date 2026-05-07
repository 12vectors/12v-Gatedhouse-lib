package com.twelvevectors.gatedhouse;

import java.util.List;

public interface RoleManager {

    // ---- role definitions --------------------------------------------------

    void createRole(String key, String name, String description);

    void deleteRole(String key);

    boolean hasRole(String key);

    List<String> listRoles();

    // ---- permission grants on a role --------------------------------------
    // service / resource / action may be null to denote a wildcard at that
    // level. (null, null, null) grants superuser-equivalent permission.

    void grantPermission(String roleKey, String service, String resource, String action);

    void revokePermission(String roleKey, String service, String resource, String action);

    // ---- role inheritance --------------------------------------------------

    void addParentRole(String childKey, String parentKey);

    void removeParentRole(String childKey, String parentKey);

    List<String> getParentRoles(String childKey);

    // ---- assignments to identities (per org) ------------------------------

    void assignToIdentity(String identityId, String orgId, String roleKey);

    void revokeFromIdentity(String identityId, String orgId, String roleKey);

    List<String> getIdentityRoles(String identityId, String orgId);

    // ---- assignments to groups (per org) ----------------------------------

    void assignToGroup(String groupId, String orgId, String roleKey);

    void revokeFromGroup(String groupId, String orgId, String roleKey);

    List<String> getGroupRoles(String groupId, String orgId);
}
