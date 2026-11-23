package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListServerException;
import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Registers realms as "Issuers" on the external status list server.
 *
 * <p>Registration runs in the background so that Keycloak startup and request threads remain
 * responsive. The first attempt starts after 1s. Failed attempts are retried with a linearly
 * growing delay: 10s, 20s, 30s, and so on.
 */
public class RealmAsIssuerRegistrationService {

    private static final Logger logger = Logger.getLogger(RealmAsIssuerRegistrationService.class);

    private static final String BACKGROUND_THREAD_NAME = "status-list-registration";

    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final long DEFAULT_INITIAL_DELAY_MS = 1_000L;
    public static final long BACKOFF_MULTIPLIER_MS = 10_000L;

    private final KeycloakSessionFactory factory;
    private final ScheduledExecutorService scheduler = createScheduler();

    /**
     * Per-realm registration state, keyed by realm {@link RealmModel#getId() id}
     */
    private final ConcurrentHashMap<String, RegistrationStatus> registrationStatuses = new ConcurrentHashMap<>();
    private final Set<String> pendingRegistrationTriggers = ConcurrentHashMap.newKeySet();

    public RealmAsIssuerRegistrationService(KeycloakSessionFactory factory) {
        this.factory = factory;
    }

    /**
     * Stops background scheduling for this service
     */
    public void close() {
        scheduler.shutdownNow();
    }

    /**
     * Creates the scheduler used for background registration attempts; overridable in tests to
     * observe scheduled attempts synchronously.
     */
    protected ScheduledExecutorService createScheduler() {
        return Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, BACKGROUND_THREAD_NAME));
    }

    /**
     * Creates an HTTP client for registration operations (background). Long timeout, no
     * HTTP-layer retries: retries and spacing are owned by the registration scheduler.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    protected CloseableHttpClient registrationClient(StatusListConfig config) {
        return CustomHttpClient.createHttpClient(config.getRegistrationTimeout(), 0, config);
    }

    /**
     * Triggers background registration for all realms.
     */
    public void triggerBackgroundRegistration() {
        try {
            KeycloakModelUtils.runJobInTransaction(
                    factory,
                    session -> session.realms().getRealmsStream().forEach(realm -> {
                        if (new StatusListConfig(realm).isEnabled()) {
                            triggerBackgroundRegistration(realm.getId(), realm.getName());
                        } else {
                            logger.debugf("Skipping status list registration for disabled realm %s", realm.getName());
                        }
                    }));
        } catch (Exception e) {
            logger.errorf(e, "Failed to list realms for background status list registration");
        }
    }

    /**
     * Triggers background registration for the given realm.
     */
    public void triggerBackgroundRegistration(RealmModel realm) {
        triggerBackgroundRegistration(realm.getId(), realm.getName());
    }

    /**
     * Triggers background registration for the realm identified by its persistent ID. Only the
     * ID and name are retained: a {@link RealmModel} from a lifecycle event may be detached by
     * the time the background transaction runs.
     */
    public void triggerBackgroundRegistration(String realmId, String realmName) {
        triggerBackgroundRegistration(realmId, realmName, DEFAULT_INITIAL_DELAY_MS, DEFAULT_MAX_RETRIES);
    }

    /**
     * Triggers a background registration for the given realm. The first attempt runs after the
     * given initial delay; failures are retried with a linearly growing delay,
     * up to the given number of retries.
     *
     * @param realm the realm to register
     * @param initialDelayMs delay before the first attempt
     * @param maxRetries maximum number of retries after the initial attempt
     */
    public void triggerBackgroundRegistration(RealmModel realm, long initialDelayMs, int maxRetries) {
        triggerBackgroundRegistration(realm.getId(), realm.getName(), initialDelayMs, maxRetries);
    }

    private void triggerBackgroundRegistration(String realmId, String realmName, long initialDelayMs, int maxRetries) {
        // Skip a completed realm. If work is already running, remember that another event
        // requested registration so a configuration update cannot be lost at the end of retries.
        RegistrationStatus existing = registrationStatuses.putIfAbsent(realmId, RegistrationStatus.RUNNING);
        if (existing != null) {
            if (existing == RegistrationStatus.RUNNING) {
                pendingRegistrationTriggers.add(realmId);
            }
            return;
        }

        // Schedule first attempt at registering the realm after `initialDelayMs`
        scheduler.schedule(
                () -> runRegistrationAttempt(new Attempt(realmId, realmName, 0, maxRetries, 0)),
                initialDelayMs,
                TimeUnit.MILLISECONDS);
    }

    /**
     * Runs one registration attempt and then updates the realm's registration status: completed
     * realms are marked COMPLETED, skipped or unmarked realms are forgotten so a later trigger
     * can start over, and still-failing realms run again later with a linearly growing delay
     * while the retry budget lasts.
     */
    protected void runRegistrationAttempt(Attempt attempt) {
        // It is a no-op if the realm was already registered.
        if (registrationStatuses.get(attempt.realmId()) == RegistrationStatus.COMPLETED) {
            return;
        }

        // Run registration in its own Keycloak session and transaction, detached from any
        // request scope, on the background thread. Resolve the realm again by ID inside this
        // transaction because models captured by RealmPostCreateEvent are detached snapshots.
        AtomicReference<RegistrationResult> result = new AtomicReference<>(RegistrationResult.FAILED);
        try {
            KeycloakModelUtils.runJobInTransaction(factory, session -> {
                RealmModel realm = session.realms().getRealm(attempt.realmId());
                if (realm == null) {
                    logger.warnf("Skipping status list registration: realm %s no longer exists", attempt.realmName());
                    result.set(RegistrationResult.REALM_MISSING);
                    return;
                }
                session.getContext().setRealm(realm);
                result.set(registerRealmAsIssuer(session, realm));
            });
        } catch (Exception e) {
            logger.errorf(e, "Error during registration for realm %s: %s", attempt.realmName(), e.getMessage());
        }

        if (result.get() == RegistrationResult.REGISTERED) {
            registrationStatuses.put(attempt.realmId(), RegistrationStatus.COMPLETED);
            pendingRegistrationTriggers.remove(attempt.realmId());
            return;
        }

        if (result.get() == RegistrationResult.DISABLED) {
            // A disabled realm has not attempted registration, so it should not spend the
            // transient-failure retry budget. Use a separate bounded gate-poll count while
            // waiting for provisioning to enable the status-list feature.
            if (attempt.gateAttempts() >= attempt.maxRetries()) {
                finishOrRestart(attempt);
                return;
            }

            Attempt next = new Attempt(
                    attempt.realmId(),
                    attempt.realmName(),
                    attempt.attempt(),
                    attempt.maxRetries(),
                    attempt.gateAttempts() + 1);
            long delayMs = BACKOFF_MULTIPLIER_MS * next.gateAttempts();
            logger.infof(
                    "Realm %s is not status-list enabled; checking configuration again in %d ms",
                    attempt.realmName(),
                    delayMs);
            scheduler.schedule(() -> runRegistrationAttempt(next), delayMs, TimeUnit.MILLISECONDS);
            return;
        }

        if (result.get() == RegistrationResult.REALM_MISSING) {
            finishOrRestart(attempt);
            return;
        }

        // Schedule a new attempt if necessary
        if (registrationStatuses.get(attempt.realmId()) == RegistrationStatus.RUNNING) {
            if (attempt.attempt() >= attempt.maxRetries()) {
                finishOrRestart(attempt);
                return;
            }

            Attempt next = new Attempt(
                    attempt.realmId(), attempt.realmName(), attempt.attempt() + 1, attempt.maxRetries(), 0);
            long delayMs = BACKOFF_MULTIPLIER_MS * next.attempt();
            logger.infof("Scheduling registration retry for realm %s in %d ms", attempt.realmName(), delayMs);
            scheduler.schedule(() -> runRegistrationAttempt(next), delayMs, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Forgets a completed attempt and starts one fresh run if a lifecycle/configuration event
     * arrived while the previous attempt was still marked RUNNING.
     */
    private void finishOrRestart(Attempt attempt) {
        registrationStatuses.remove(attempt.realmId(), RegistrationStatus.RUNNING);
        if (pendingRegistrationTriggers.remove(attempt.realmId())) {
            triggerBackgroundRegistration(attempt.realmId(), attempt.realmName());
        }
    }

    /** Performs one registration attempt and reports its result to the retry scheduler. */
    private RegistrationResult registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();
        StatusListConfig config = new StatusListConfig(realm);
        if (!config.isEnabled()) {
            logger.infof("Status list registration is disabled for realm %s; waiting for configuration", realmName);
            return RegistrationResult.DISABLED;
        }

        logger.infof("Starting registration for realm: %s", realmName);
        try (CloseableHttpClient http = registrationClient(config)) {
            StatusListServiceAndKey service = getStatusListService(session, realm, config, http);
            if (service == null) {
                return RegistrationResult.FAILED;
            }

            if (!service.service().checkServerHealth()) {
                logger.warn("Status list server health check failed for realm: " + realmName);
                return RegistrationResult.FAILED;
            }

            service.service().registerIssuer(config.getTokenIssuerId(), service.jwk());
            logger.info("Successfully registered realm as issuer: " + realmName);
            return RegistrationResult.REGISTERED;
        } catch (StatusListServerException | StatusListException | IOException e) {
            logger.errorf(e, "Registration failed for realm: %s", realmName);
            return RegistrationResult.FAILED;
        }
    }

    /**
     * Builds the status list service facade for the realm: resolves the realm signing key
     * (unresolvable is treated as a transient condition, e.g. keys are not ready yet, and simply
     * means retrying later), creates the JWT authentication token, and wraps the given
     * registration HTTP client in the facade.
     */
    private StatusListServiceAndKey getStatusListService(
            KeycloakSession session, RealmModel realm, StatusListConfig config, CloseableHttpClient http) {
        CryptoIdentityService.KeyData keyData;
        try {
            keyData = CryptoIdentityService.getRealmKeyData(session, realm);
        } catch (StatusListException e) {
            logger.warnf("Key extraction failed for realm: %s. Registration will be retried later.", realm.getName());
            return null;
        }

        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                config.getServerUrl(), cryptoIdentityService.getJwtToken(config), http, null);
        return new StatusListServiceAndKey(new StatusListService(httpClient), keyData.jwk());
    }

    /**
     * Tracks per-realm registration state: running, or completed (successfully).
     */
    private enum RegistrationStatus {
        RUNNING,
        COMPLETED
    }

    private enum RegistrationResult {
        REGISTERED,
        DISABLED,
        REALM_MISSING,
        FAILED
    }

    /**
     * Bundles the status list service facade with the realm's public JWK for issuer registration.
     **/
    private record StatusListServiceAndKey(StatusListService service, JWK jwk) {}

    /**
     * Progress marker threaded through the scheduler: realm identity, failed registration
     * attempt count, bounded disabled-gate checks, and the shared retry limit.
     */
    public record Attempt(String realmId, String realmName, int attempt, int maxRetries, int gateAttempts) {}
}
