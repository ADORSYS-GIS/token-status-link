package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Factory for creating CredentialRevocationResourceProvider instances.
 * This registers the credential revocation REST endpoints with Keycloak.
 */
public class CredentialRevocationResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(CredentialRevocationResourceProviderFactory.class);
    private static final String PROVIDER_ID = "credential-revocation";
    private final Set<String> registeredRealms = ConcurrentHashMap.newKeySet();
    private KeycloakSessionFactory sessionFactory;
    private volatile boolean initialized = false;

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

    /**
     * Checks the health status of the status list server before proceeding with operations.
     *
     * @param serverUrl the server URL to check
     * @return true if the server is healthy, false otherwise
     */
    private boolean checkServerHealth(String serverUrl) {
        String healthUrl = serverUrl.endsWith("/") ? serverUrl + "health" : serverUrl + "/health";
        logger.debugf("Checking server health at: %s", healthUrl);

        try (CloseableHttpClient httpClient = CustomHttpClient.getHttpClient()) {
            HttpGet httpGet = new HttpGet(healthUrl);

            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                EntityUtils.consume(response.getEntity()); // Ensure response body is consumed

                if (statusCode == 200) {
                    logger.debug("Server health check passed");
                    return true;
                } else {
                    logger.warnf("Server health check failed: status %d", statusCode);
                    return false;
                }
            });
        } catch (IOException e) {
            // IOException covers connection errors, timeouts, etc.
            logger.warnf("Error during server health check at %s: %s", healthUrl, e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error during server health check", e);
            return false;
        }
    }

    protected void performSleep(long millis) throws InterruptedException {
        Thread.sleep(millis);
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

            if (!checkServerHealth(config.getServerUrl())) {
                logger.warnf("Health check failed for server: %s", config.getServerUrl());
                return false;
            }

            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
            StatusListService statusListService = new StatusListService(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getHttpClient()
            );

            // Get realm's public key and algorithm
            KeyManager keyManager = session.keys();
            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
            if (activeKey == null) {
                logger.warn("No active key found for realm: " + realm.getName());
                return false;
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
                    return false;
                }
            }

            String algorithm = activeKey.getAlgorithm() != null ? activeKey.getAlgorithm() : "RS256";

            if (publicKey == null) {
                logger.warn("No public key available for realm: " + realm.getName());
                return false;
            }

            // Register the realm as an issuer
            statusListService.registerIssuer(config.getTokenIssuerId(), publicKey, algorithm);
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
        logger.info("Closing CredentialRevocationResourceProviderFactory");
        registeredRealms.clear();
        initialized = false;
    }
}
