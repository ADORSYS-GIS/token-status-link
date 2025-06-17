package com.adorsys.keycloakstatuslist.events;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import org.keycloak.crypto.Algorithm;

/**
 * Factory for creating TokenStatusEventListenerProvider instances.
 */
public class TokenStatusEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProviderFactory.class);
    private static final String PROVIDER_ID = "token-status-event-listener";
    private final Set<String> registeredRealms = ConcurrentHashMap.newKeySet();
    private KeycloakSessionFactory sessionFactory;
    private volatile boolean initialized = false;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        logger.info("Creating TokenStatusEventListenerProvider");
        return new TokenStatusEventListenerProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing TokenStatusEventListenerProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("Post-initializing TokenStatusEventListenerProviderFactory");
        this.sessionFactory = factory;
        
        // Initialize realms directly since we're already in the postInit phase
        // which means Keycloak's database is ready
        try {
            initializeRealms();
        } catch (Exception e) {
            logger.error("Error during initialization", e);
        }
    }

    private void initializeRealms() {
        if (initialized) {
            return;
        }

        logger.info("Starting realm initialization");
        
        try (KeycloakSession session = sessionFactory.create()) {
            session.getTransactionManager().begin();
            
            // Get all realms
            var realms = session.realms().getRealmsStream().toList();
            logger.info("Found " + realms.size() + " realms to register");
            
            // Register each realm
            for (RealmModel realm : realms) {
                try {
                    registerRealmAsIssuer(session, realm);
                } catch (Exception e) {
                    logger.error("Failed to register realm: " + realm.getName(), e);
                }
            }
            
            session.getTransactionManager().commit();
            initialized = true;
            logger.info("Successfully completed realm initialization");
        } catch (Exception e) {
            logger.error("Error during realm initialization", e);
        }
    }

    protected void performSleep(long millis) throws InterruptedException {
        Thread.sleep(millis);
    }

    private void registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        try {
            StatusListConfig config = new StatusListConfig(realm);
            if (!config.isEnabled()) {
                logger.debug("Status list service is disabled for realm: " + realm.getName());
                return;
            }

            StatusListService statusListService = new StatusListService(
                    config.getServerUrl(),
                    config.getAuthToken(),
                    config.getConnectTimeout(),
                    config.getReadTimeout(),
                    config.getRetryCount()
            );

            // Check if the realm is already registered in the status list service
            if (statusListService.isIssuerRegistered(realm.getName())) {
                logger.debug("Realm already registered as issuer in status list service: " + realm.getName());
                registeredRealms.add(realm.getName());
                return;
            }

            // Get realm's public key and algorithm
            KeyManager keyManager = session.keys();
            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
            if (activeKey == null) {
                logger.warn("No active key found for realm: " + realm.getName());
                return;
            }

            // Convert public key to PEM format
            String publicKey = null;
            if (activeKey.getPublicKey() != null) {
                try {
                    byte[] encoded = activeKey.getPublicKey().getEncoded();
                    String base64 = java.util.Base64.getEncoder().encodeToString(encoded);
                    publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                              base64.replaceAll("(.{64})", "$1\n") +
                              "\n-----END PUBLIC KEY-----";
                } catch (Exception e) {
                    logger.error("Failed to convert public key to PEM format for realm: " + realm.getName(), e);
                    return;
                }
            }

            String algorithm = activeKey.getAlgorithm() != null ? activeKey.getAlgorithm() : "RS256";

            if (publicKey == null) {
                logger.warn("No public key available for realm: " + realm.getName());
                return;
            }

            // Register the realm as an issuer
            statusListService.registerIssuer(realm.getName(), publicKey, algorithm);
            registeredRealms.add(realm.getName());
            logger.info("Successfully registered realm as issuer: " + realm.getName());
        } catch (StatusListException e) {
            logger.error("Failed to register realm as issuer: " + realm.getName(), e);
        }
    }

    @Override
    public void close() {
        logger.info("Closing TokenStatusEventListenerProviderFactory");
        registeredRealms.clear();
        initialized = false;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}