package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the status list admin resource provider.
 * Registers the provider under the ID "status-list-admin", making the endpoint
 * available at /realms/{realm}/status-list-admin.
 */
public class StatusListAdminResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "status-list-admin";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new StatusListAdminResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization required
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization required
    }

    @Override
    public void close() {
        // No resources to close
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
