package com.adorsys.keycloakstatuslist.events;

import java.util.Set;
import java.util.HashSet;

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
import org.keycloak.services.managers.RealmManager;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import com.adorsys.keycloakstatuslist.exception.StatusListException;

/**
 * Factory for creating TokenStatusEventListenerProvider instances.
 */
public class TokenStatusEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Logger logger = Logger.getLogger(TokenStatusEventListenerProviderFactory.class);

    // Provider ID used in Keycloak configuration
    public static final String PROVIDER_ID = "token-status-event-listener";

    // Set of realms that have been registered as issuers
    private final Set<String> registeredRealms = new HashSet<>();

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
        
        // Register all realms as issuers
        try (KeycloakSession session = factory.create()) {
            session.getTransactionManager().begin();
            try {
                RealmManager realmManager = new RealmManager(session);
                for (RealmModel realm : session.realms().getRealmsStream().toList()) {
                    registerRealmAsIssuer(session, realm);
                }
                session.getTransactionManager().commit();
            } catch (Exception e) {
                session.getTransactionManager().rollback();
                logger.error("Error during post-initialization", e);
            }
        } catch (Exception e) {
            logger.error("Error creating session during post-initialization", e);
        }
    }

    private void registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        if (registeredRealms.contains(realm.getName())) {
            logger.debug("Realm already registered as issuer: " + realm.getName());
            return;
        }

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

            // Get realm's public key and algorithm
            KeyManager keyManager = session.keys();
            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, "RS256");
            if (activeKey == null) {
                logger.warn("No active key found for realm: " + realm.getName());
                return;
            }

            String publicKey = activeKey.getPublicKey() != null ? activeKey.getPublicKey().toString() : null;
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
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}