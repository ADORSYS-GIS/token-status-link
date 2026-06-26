package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Realm resource provider that exposes the status list admin endpoint
 * under the realm's REST API at /realms/{realm}/status-list-admin/credentials.
 */
public class StatusListAdminResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public StatusListAdminResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new StatusListAdminResource(session);
    }

    @Override
    public void close() {
        // No resources to close
    }
}
