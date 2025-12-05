package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.RevocationRecordService; // Import the service
import com.adorsys.keycloakstatuslist.service.RevocationRecordService.KeyData;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Overrides the OID4VC protocol factory to inject a custom revocation endpoint into the standard /protocol/openid-connect/revoke path.
 * Handles realm issuer registration at startup for status list integration.
 */
public class CredentialRevocationResourceProviderFactory extends OIDCLoginProtocolFactory {

    private static final Logger logger = Logger.getLogger(CredentialRevocationResourceProviderFactory.class);
    private final Set<String> registeredRealms = ConcurrentHashMap.newKeySet();
    private volatile boolean initialized = false;

    /**
     * defines the option-order in the admin-ui
     */
    @Override
    public int order() {
        return OIDCLoginProtocolFactory.UI_ORDER + 300;
    }

    @Override
    public Object createProtocolEndpoint(KeycloakSession session, EventBuilder event) {
        return new CustomOIDCLoginProtocolService(session, event);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);
        logger.info("Post-initializing CredentialRevocationResourceProviderFactory for standard revocation endpoint override");

        // Initialize realms directly since we're already in the postInit phase
        // which means Keycloak's database is ready
        try {
            factory.register(event -> {
                if (event instanceof PostMigrationEvent) {
                    initializeRealms(factory);
                }
            });
        } catch (Exception e) {
            logger.error("Error during initialization", e);
        }
    }

    private void initializeRealms(KeycloakSessionFactory factory) {
        if (initialized) {
            return;
        }

        logger.info("Starting realm initialization");

        try (KeycloakSession session = factory.create()) {
            session.getTransactionManager().begin();

            // Get all realms
            List<RealmModel> realms = session.realms().getRealmsStream().toList();
            logger.info("Found " + realms.size() + " realms to register");

            // Track registration results
            int totalRealms = realms.size();
            int successfulRegistrations = 0;
            int failedRegistrations = 0;
            int skippedRegistrations = 0;
            List<String> failedRealmNames = new ArrayList<>();
            List<String> skippedRealmNames = new ArrayList<>();

            // Register each realm
            for (RealmModel realm : realms) {
                boolean registrationResult = registerRealmAsIssuer(session, realm);
                if (registrationResult) {
                    successfulRegistrations++;
                } else {
                    // Check if this was due to server unavailability
                    if (realm.getAttribute("status-list-enabled") != null &&
                            "true".equals(realm.getAttribute("status-list-enabled"))) {
                        skippedRegistrations++;
                        skippedRealmNames.add(realm.getName());
                    } else {
                        failedRegistrations++;
                        failedRealmNames.add(realm.getName());
                    }
                }
            }

            session.getTransactionManager().commit();

            // Report results based on registration outcomes
            logger.info("Registration results - Total: " + totalRealms +
                    ", Successful: " + successfulRegistrations +
                    ", Failed: " + failedRegistrations +
                    ", Skipped: " + skippedRegistrations);

            if (failedRegistrations == 0 && skippedRegistrations == 0) {
                logger.info("Successfully completed realm initialization - all " + totalRealms + " realms registered");
                initialized = true;
            } else if (successfulRegistrations == 0 && failedRegistrations > 0) {
                logger.error("Realm initialization failed - all " + totalRealms
                        + " realms failed to register. Failed realms: " + String.join(", ", failedRealmNames));
            } else {
                if (skippedRegistrations > 0) {
                    logger.warn("Realm initialization completed with some realms skipped due to server unavailability - "
                            + successfulRegistrations + " successful, " + skippedRegistrations + " skipped. Skipped realms: "
                            + String.join(", ", skippedRealmNames));
                }
                if (failedRegistrations > 0) {
                    logger.warn("Realm initialization completed with some failures - "
                            + successfulRegistrations + " successful, " + failedRegistrations + " failed. Failed realms: "
                            + String.join(", ", failedRealmNames));
                }
                initialized = true;
            }
        } catch (Exception e) {
            logger.error("Error during realm initialization", e);
        }
    }

    private boolean registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        if (registeredRealms.contains(realm.getName())) {
            logger.debug("Realm already registered as issuer: " + realm.getName());
            return true; // Already registered, no need to re-register
        }

        try {
            StatusListConfig config = new StatusListConfig(realm);
            if (!config.isEnabled()) {
                logger.debug("Status list service is disabled for realm: " + realm.getName());
                return true; // Disabled, no need to register
            }

            KeyData keyData;
            try {
                keyData = RevocationRecordService.getRealmKeyData(session, realm);
            } catch (StatusListException e) {
                logger.warn("Could not retrieve valid signing key for realm: " + realm.getName() + ". " + e.getMessage());
                return false;
            }

            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
            StatusListService statusListService = new StatusListService(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getHttpClient()
            );

            // Check if the status list server is reachable
            if (!statusListService.checkServerHealth()) {
                logger.warn("Status list server is not reachable for realm: " + realm.getName());
                return false;
            }

            // Register the realm as an issuer using the retrieved JWK
            statusListService.registerIssuer(config.getTokenIssuerId(), keyData.jwk(), keyData.algorithm());
            registeredRealms.add(realm.getName());
            logger.info("Successfully registered realm as issuer: " + realm.getName());
            return true;
        } catch (StatusListException e) {
            logger.error("Failed to register realm as issuer: " + realm.getName(), e);
            return false;
        }
    }

    @Override
    public void close() {
        super.close();
        logger.info("Closing CredentialRevocationResourceProviderFactory");
        registeredRealms.clear();
        initialized = false;
    }
}