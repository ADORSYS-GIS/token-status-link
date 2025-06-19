package com.adorsys.keycloakstatuslist;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class StatusListJpaEntityProviderFactory implements JpaEntityProviderFactory {

    private static final String ID = "status-list-jpa-entity-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        System.out.println("DEBUG: Creating StatusListJpaEntityProvider");
        return new StatusListJpaEntityProvider();
    }

    @Override
    public void init(Config.Scope config) {
        System.out.println("DEBUG: Initializing StatusListJpaEntityProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        System.out.println("DEBUG: Post-initializing StatusListJpaEntityProviderFactory");
    }

    @Override
    public void close() {
        System.out.println("DEBUG: Closing StatusListJpaEntityProviderFactory");
    }

    @Override
    public String getId() {
        return ID;
    }
}