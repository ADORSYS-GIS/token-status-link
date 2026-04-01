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
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;

/**
 * Custom OIDC Protocol Factory with:
 * - Startup registration
 * - New realm registration
 * - Lazy (on-demand) registration
 * - Thread-safe per-realm locking
 */
public class CustomOIDCLoginProtocolFactory extends OIDCLoginProtocolFactory {

    private static final Logger logger = Logger.getLogger(CustomOIDCLoginProtocolFactory.class);

    private final Set<String> registeredRealms = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Object> registrationLocks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastAttemptTime = new ConcurrentHashMap<>();
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    private static final ExecutorService executor = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors()), r -> new Thread(r, "status-list-init"));

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
        String realmName = realm.getName();

        // Lazy registration in background if not already registered and not in cooldown
        if (!registeredRealms.contains(realmName)) {
            StatusListConfig config = new StatusListConfig(realm);
            Long lastTime = lastAttemptTime.get(realmName);
            long cooldown = config.getRegistrationCooldownMs();

            if (lastTime == null || System.currentTimeMillis() - lastTime >= cooldown) {
                // Atomic check for in-flight tasks to prevent multiple scheduled tasks for the same realm
                if (inFlight.add(realmName)) {
                    logger.debugf("Scheduling lazy background registration for realm: %s", realmName);
                    KeycloakSessionFactory factory = session.getKeycloakSessionFactory();
                    runAsync(() -> {
                        try (KeycloakSession bgSession = factory.create()) {
                            bgSession.getTransactionManager().begin();
                            try {
                                RealmModel bgRealm = bgSession.realms().getRealmByName(realmName);
                                if (bgRealm != null) {
                                    ensureRealmRegistered(bgSession, bgRealm);
                                    bgSession.getTransactionManager().commit();
                                } else {
                                    bgSession.getTransactionManager().rollback();
                                }
                            } catch (Exception e) {
                                if (bgSession.getTransactionManager().isActive()) {
                                    bgSession.getTransactionManager().rollback();
                                }
                                throw e;
                            }
                        } catch (Exception e) {
                            logger.errorf(
                                    "Error during lazy background registration for realm %s: %s",
                                    realmName, e.getMessage(), e);
                        } finally {
                            inFlight.remove(realmName);
                        }
                    });
                }
            }
        }

        CredentialRevocationService revocationService = new CredentialRevocationService(session);
        return new CustomOIDCLoginProtocolService(session, event, revocationService);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);

        try {
            factory.register(event -> {
                if (event instanceof PostMigrationEvent) {
                    initializeRealms(factory);
                }
            });
        } catch (Exception e) {
            logger.error("Error during initialization listener registration", e);
        }
    }

    private void initializeRealms(KeycloakSessionFactory factory) {
        if (initialized) {
            return;
        }

        // Run in a background thread to avoid blocking Keycloak boot
        runAsync(() -> {
            logger.info("Starting background realm initialization");
            try (KeycloakSession session = factory.create()) {
                session.getTransactionManager().begin();
                try {
                    List<RealmModel> realms = session.realms().getRealmsStream().toList();

                    for (RealmModel realm : realms) {
                        ensureRealmRegistered(session, realm);
                    }

                    session.getTransactionManager().commit();
                    initialized = true;
                    logger.info("Successfully completed initial background realm registration checks");
                } catch (Exception e) {
                    if (session.getTransactionManager().isActive()) {
                        session.getTransactionManager().rollback();
                    }
                    throw e;
                }
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
     * Synchronous implementation that uses a per-realm lock to prevent concurrent
     * registration attempts. Should be called from a background thread or a
     * request context that can afford a delay.
     */
    private void ensureRealmRegistered(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();

        if (registeredRealms.contains(realmName)) {
            return;
        }

        // Quick check outside lock
        StatusListConfig config = new StatusListConfig(realm);
        Long lastTime = lastAttemptTime.get(realmName);
        long cooldown = config.getRegistrationCooldownMs();

        if (lastTime != null && System.currentTimeMillis() - lastTime < cooldown) {
            return;
        }

        // Use a lock object per realm to avoid parallel registration attempts for the same realm
        Object lock = registrationLocks.computeIfAbsent(realmName, k -> new Object());

        synchronized (lock) {
            if (!registeredRealms.contains(realmName)) {
                // Check cooldown again inside lock to prevent "waiting herd" from retrying immediately
                lastTime = lastAttemptTime.get(realmName);
                if (lastTime != null && System.currentTimeMillis() - lastTime < cooldown) {
                    return;
                }

                // Mark current attempt time
                lastAttemptTime.put(realmName, System.currentTimeMillis());

                registerRealmAsIssuer(session, realm);
            }
        }
    }

    private boolean registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();

        if (registeredRealms.contains(realmName)) {
            return true;
        }

        try {
            StatusListConfig config = new StatusListConfig(realm);

            if (!config.isEnabled()) {
                return true;
            }

            CryptoIdentityService.KeyData keyData;
            try {
                keyData = CryptoIdentityService.getRealmKeyData(session, realm);
            } catch (StatusListException e) {
                logger.warn("Key extraction failed for realm: " + realmName);
                return false;
            }

            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
            CircuitBreaker circuitBreaker = CircuitBreaker.getInstance(config);

            StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getRegistrationHttpClient(config),
                    circuitBreaker);

            StatusListService statusListService = new StatusListService(httpClient);

            if (!statusListService.checkServerHealth()) {
                return false;
            }

            statusListService.registerIssuer(config.getTokenIssuerId(), keyData.jwk());

            registeredRealms.add(realmName);

            registrationLocks.remove(realmName);

            return true;

        } catch (StatusListServerException | StatusListException e) {
            logger.error("Registration failed for realm: " + realmName, e);
            return false;
        }
    }

    @Override
    public void close() {
        super.close();
        registeredRealms.clear();
        registrationLocks.clear();
        lastAttemptTime.clear();
        inFlight.clear();
        initialized = false;
    }
}
