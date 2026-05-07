package com.twelvevectors.gatedhouse;

import java.util.List;

public interface GroupManager {

    // ---- group definitions (per org) --------------------------------------

    void createGroup(String groupId, String orgId, String name, String description);

    void deleteGroup(String groupId, String orgId);

    boolean hasGroup(String groupId, String orgId);

    List<String> listGroups(String orgId);

    // ---- group membership -------------------------------------------------

    void addIdentityToGroup(String groupId, String orgId, String identityId);

    void removeIdentityFromGroup(String groupId, String orgId, String identityId);

    List<String> getGroupMembers(String groupId, String orgId);

    List<String> getIdentityGroups(String identityId, String orgId);
}
