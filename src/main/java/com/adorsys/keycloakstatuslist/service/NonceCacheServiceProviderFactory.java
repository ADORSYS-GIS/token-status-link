package com.adorsys.keycloakstatuslist.service;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the NonceCacheService.
 * Implements RealmResourceProviderFactory so Keycloak can discover it via standard SPI.
 */
public class NonceCacheServiceProviderFactory implements RealmResourceProviderFactory {
    
    private static final Logger logger = Logger.getLogger(NonceCacheServiceProviderFactory.class);
    public static final String PROVIDER_ID = "nonce-cache";
    
    // Singleton instance of the service (shared across all realms and sessions)
    private static NonceCacheService instance;
    
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        if (instance == null) {
            synchronized (NonceCacheServiceProviderFactory.class) {
                if (instance == null) {
                    instance = new NonceCacheService();
                    logger.info("Created NonceCacheService singleton instance");
                }
            }
        }
        logger.debugf("Returning NonceCacheService instance for session");
        return instance;
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
        if (instance != null) {
            instance.close();
            instance = null;
            logger.info("Closed NonceCacheService");
        }
    }
    
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
