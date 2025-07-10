package com.adorsys.keycloakstatuslist;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.jboss.logging.Logger;

public final class StatusListJpaEntityProviderFactory implements JpaEntityProviderFactory {

    public static final String ID = "status-list-jpa-entity-provider";

    private static final Logger logger = Logger.getLogger(StatusListJpaEntityProviderFactory.class);

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        logger.debug("Creating StatusListJpaEntityProvider");
        return new StatusListJpaEntityProvider();
    }

    @Override
    public void init(Config.Scope config) {
        logger.debug("Initializing StatusListJpaEntityProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.debug("Post-initializing StatusListJpaEntityProviderFactory");
    }

    @Override
    public void close() {
        logger.debug("Closing StatusListJpaEntityProviderFactory");
    }

    @Override
    public String getId() {
        return ID;
    }
}
