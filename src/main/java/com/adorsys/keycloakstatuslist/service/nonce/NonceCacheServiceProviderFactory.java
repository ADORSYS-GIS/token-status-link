package com.adorsys.keycloakstatuslist.service.nonce;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the NonceCacheService.
 * Implements RealmResourceProviderFactory so Keycloak can discover it via standard SPI.
 * Creates a per-session instance so each request uses that session's SingleUseObjectProvider.
 */
public class NonceCacheServiceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(NonceCacheServiceProviderFactory.class);
    public static final String PROVIDER_ID = "nonce-cache";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        logger.debugf("Creating NonceCacheService for session");
        return new NonceCacheService(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing NonceCacheServiceProviderFactory with ID: " + PROVIDER_ID);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("Post-initializing NonceCacheServiceProviderFactory");
    }

    @Override
    public void close() {
        // No singleton to close; instances are session-scoped.
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
