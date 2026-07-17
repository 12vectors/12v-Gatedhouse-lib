// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import java.util.List;

public interface PermissionCatalog {

    // ---- services ----------------------------------------------------------

    void addService(String service, String description);

    void removeService(String service);

    boolean hasService(String service);

    List<String> listServices();

    // ---- resources ---------------------------------------------------------

    void addResource(String service, String resource, String description);

    void removeResource(String service, String resource);

    boolean hasResource(String service, String resource);

    List<String> listResources(String service);

    // ---- actions -----------------------------------------------------------

    void addAction(String service, String resource, String action, String description);

    void removeAction(String service, String resource, String action);

    boolean hasAction(String service, String resource, String action);

    List<String> listActions(String service, String resource);
}
