package com.adorsys.keycloakstatuslist;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

public class StatusListIndexStorageProviderFactory implements ProviderFactory<StatusListIndexStorageProvider> {

    @Override
    public StatusListIndexStorageProvider create(KeycloakSession session) {
        return new StatusListIndexStorageProvider(session);
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
        return "status-list-index-storage";
    }
}