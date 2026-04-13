package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;

/**
 * Overrides the OID4VC protocol factory to inject a custom revocation endpoint into the standard
 * /protocol/openid-connect/revoke path.
 *
 * This factory also manages the registration of realms as "Issuers" on the external status list server.
 * Registration is handled in the background to ensure Keycloak startup and OIDC request threads
 * remain responsive.
 */
public class CustomOIDCLoginProtocolFactory extends OIDCLoginProtocolFactory {

    private static final Logger logger = Logger.getLogger(CustomOIDCLoginProtocolFactory.class);

    private final Set<String> registeredRealms = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Object> registrationLocks = new ConcurrentHashMap<>();
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    private static final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> new Thread(r, "status-list-init"));

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
        RealmModel realm = session.getContext().getRealm();

        // Trigger background registration. Non-blocking to keep UI responsive.
        triggerBackgroundRegistration(session.getKeycloakSessionFactory(), realm.getName());

        CredentialRevocationService revocationService = new CredentialRevocationService(session);
        return new CustomOIDCLoginProtocolService(session, event, revocationService);
    }

    /**
     * Triggers a background registration task for the given realm if it's not already registered
     * and not currently in progress.
     *
     * @param factory the KeycloakSessionFactory used to create new background sessions
     * @param realmName the name of the realm to register
     */
    private void triggerBackgroundRegistration(KeycloakSessionFactory factory, String realmName) {
        // Fast path for already registered realms
        if (registeredRealms.contains(realmName)) {
            return;
        }

        // Atomic check to prevent redundant task scheduling in the executor
        if (inFlight.add(realmName)) {
            runAsync(() -> {
                // Background tasks MUST create their own session because the original request session
                // from the OIDC endpoint will be closed or detached by the time this thread executes.
                try (KeycloakSession bgSession = factory.create()) {
                    bgSession.getTransactionManager().begin();
                    try {
                        RealmModel realm = bgSession.realms().getRealmByName(realmName);
                        if (realm != null) {
                            ensureRealmRegistered(bgSession, realm);
                        }
                        bgSession.getTransactionManager().commit();
                    } catch (Exception e) {
                        if (bgSession.getTransactionManager().isActive()) {
                            bgSession.getTransactionManager().rollback();
                        }
                        logger.errorf(
                                "Error during background registration for realm %s: %s", realmName, e.getMessage(), e);
                    } finally {
                        inFlight.remove(realmName);
                    }
                }
            });
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);

        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                logger.info("Startup/Migration detected. Initializing status list realms.");
                initializeRealms(factory);
            } else if (event instanceof RealmModel.RealmPostCreateEvent realmEvent) {
                RealmModel realm = realmEvent.getCreatedRealm();
                logger.infof("New realm created: %s. Triggering background registration.", realm.getName());
                triggerBackgroundRegistration(factory, realm.getName());
            }
        });
    }

    private void initializeRealms(KeycloakSessionFactory factory) {
        if (initialized) {
            return;
        }

        runAsync(() -> {
            logger.info("Checking existing realms for status list registration");
            try (KeycloakSession session = factory.create()) {
                // Only read realm names from DB to minimize session footprint
                List<String> realmNames = KeycloakModelUtils.runJobInTransactionWithResult(factory, s -> s.realms()
                        .getRealmsStream()
                        .map(RealmModel::getName)
                        .toList());

                for (String realmName : realmNames) {
                    triggerBackgroundRegistration(factory, realmName);
                }
                initialized = true;
                logger.info("Successfully scheduled registration checks for all existing realms.");
            } catch (Exception e) {
                logger.error("Error during background realm initialization", e);
            }
        });
    }

    /**
     * Helper to run a task asynchronously. Overridden in tests to run synchronously.
     */
    protected void runAsync(Runnable runnable) {
        executor.execute(runnable);
    }

    /**
     * Ensures the realm is registered as an issuer.
     * Includes health checks and circuit breaker gating to prevent redundant or failing calls.
     *
     * @param session the KeycloakSession to use
     * @param realm the realm to register
     * @return true if successful or already registered
     */
    private boolean ensureRealmRegistered(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();

        if (registeredRealms.contains(realmName)) {
            return true;
        }

        // Per-realm lock ensures consistency if the execution policy ever changes
        // or if synchronous calls are mixed in.
        Object lock = registrationLocks.computeIfAbsent(realmName, k -> new Object());

        synchronized (lock) {
            if (registeredRealms.contains(realmName)) {
                return true;
            }

            StatusListConfig config = new StatusListConfig(realm);
            if (!config.isEnabled()) {
                return true;
            }

            // Integrate with project's CircuitBreaker for failure cooldown.
            CircuitBreaker cb = CircuitBreaker.getInstance(
                    "RegCooldown-" + realm.getId(),
                    1, // failureThreshold
                    300, // 5 minute window
                    (int) (config.getRegistrationCooldownMs() / 1000));

            try {
                cb.checkState();
                if (registerRealmAsIssuer(session, realm)) {
                    cb.recordSuccess();
                    return true;
                } else {
                    cb.recordFailure();
                    return false;
                }
            } catch (CircuitBreaker.CircuitBreakerOpenException e) {
                logger.debugf("Registration for realm %s skipped due to cooldown.", realmName);
                return false;
            }
        }
    }

    private boolean registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();
        logger.info("Starting registration for realm: " + realmName);

        try {
            StatusListConfig config = new StatusListConfig(realm);

            CryptoIdentityService.KeyData keyData;
            try {
                keyData = CryptoIdentityService.getRealmKeyData(session, realm);
            } catch (StatusListException e) {
                logger.warn("Key extraction failed for realm: " + realmName + ". Registration will be retried later.");
                return false;
            }

            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);

            // Separate CircuitBreaker for HTTP calls vs. registration cooldown.
            CircuitBreaker httpClientCB = CircuitBreaker.getInstance(config);

            StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getRegistrationHttpClient(config),
                    httpClientCB);

            StatusListService statusListService = new StatusListService(httpClient);

            if (!statusListService.checkServerHealth()) {
                logger.warn("Status list server health check failed for realm: " + realmName);
                return false;
            }
            // Register the realm as an issuer using the retrieved public key
            statusListService.registerIssuer(config.getTokenIssuerId(), keyData.jwk());

            registeredRealms.add(realmName);
            logger.info("Successfully registered realm as issuer: " + realmName);

            // Once registered, we no longer need the lock for this realm.
            registrationLocks.remove(realmName);

            return true;
        } catch (StatusListServerException | StatusListException e) {
            logger.error("Registration failed for realm: " + realmName + ". Error: " + e.getMessage(), e);
            return false;
        }
    }

    @Override
    public void close() {
        super.close();
        registeredRealms.clear();
        registrationLocks.clear();
        inFlight.clear();
        initialized = false;
    }
}
