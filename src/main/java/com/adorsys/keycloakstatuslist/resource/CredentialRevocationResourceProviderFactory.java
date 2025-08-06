package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.jboss.logging.Logger;

/**
 * Factory for creating CredentialRevocationResourceProvider instances.
 * This registers the credential revocation REST endpoints with Keycloak.
 */
public class CredentialRevocationResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(CredentialRevocationResourceProviderFactory.class);
    private static final String PROVIDER_ID = "credential-revocation";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        logger.debug("Creating CredentialRevocationResourceProvider");
        return new CredentialRevocationResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing CredentialRevocationResourceProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("Post-initializing CredentialRevocationResourceProviderFactory");
    }

    @Override
    public void close() {
        logger.info("Closing CredentialRevocationResourceProviderFactory");
    }
} 
