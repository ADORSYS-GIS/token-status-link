package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListServerException;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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
 * responsive. Failures are retried with a linearly growing delay:
 * 1s, then 10s, 20s, 30s, and so on.
 */
public class RealmAsIssuerRegistrationService {

    private static final Logger logger = Logger.getLogger(RealmAsIssuerRegistrationService.class);

    private static final String BACKGROUND_THREAD_NAME = "status-list-registration";

    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final long DEFAULT_INITIAL_DELAY_MS = 1_000L;
    public static final long BACKOFF_MULTIPLIER_MS = 10_000L;

    private final KeycloakSessionFactory factory;
    private final ScheduledExecutorService scheduler = createScheduler();
    private final ConcurrentHashMap<String, RegistrationStatus> registrationStatuses = new ConcurrentHashMap<>();

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
            KeycloakModelUtils.runJobInTransaction(factory, session -> session.realms()
                    .getRealmsStream()
                    .map(RealmModel::getName)
                    .forEach(this::triggerBackgroundRegistration));
        } catch (Exception e) {
            logger.errorf(e, "Failed to list realms for background status list registration");
        }
    }

    /**
     * Triggers background registration for the given realm.
     */
    public void triggerBackgroundRegistration(String realmName) {
        triggerBackgroundRegistration(realmName, DEFAULT_INITIAL_DELAY_MS, DEFAULT_MAX_RETRIES);
    }

    /**
     * Triggers a background registration for the given realm. The first attempt runs after the
     * given initial delay; failures are retried with a linearly growing delay,
     * up to the given number of retries.
     *
     * @param realmName name of the realm to register
     * @param initialDelayMs delay before the first attempt
     * @param maxRetries maximum number of retries after the initial attempt
     */
    public void triggerBackgroundRegistration(String realmName, long initialDelayMs, int maxRetries) {
        // Skip if the realm was already registered or registration was already started for the realm
        if (registrationStatuses.putIfAbsent(realmName, RegistrationStatus.RUNNING) != null) {
            return;
        }

        // Schedule first attempt at registering the realm after `initialDelayMs`
        scheduler.schedule(
                () -> runRegistrationAttempt(new Attempt(realmName, 0, maxRetries)),
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
        String realmName = attempt.realmName();

        // It is a no-op if the realm was already registered.
        if (registrationStatuses.get(realmName) == RegistrationStatus.COMPLETED) {
            return;
        }

        // Run registration in its own Keycloak session and transaction, detached from any
        // request scope, on the background thread.
        try {
            KeycloakModelUtils.runJobInTransaction(factory, session -> {
                RealmModel realm = session.realms().getRealmByName(realmName);
                if (realm == null) {
                    // Realm vanished: drop the entry so a same-named realm can register again.
                    registrationStatuses.remove(realmName);
                    return;
                }

                session.getContext().setRealm(realm);
                registerRealmAsIssuer(session, realm);
            });
        } catch (Exception e) {
            logger.errorf(e, "Error during registration for realm %s: %s", realmName, e.getMessage());
        }

        // Schedule a new attempt if necessary
        if (registrationStatuses.get(realmName) == RegistrationStatus.RUNNING) {
            if (attempt.attempt() >= attempt.maxRetries()) {
                registrationStatuses.remove(realmName);
                return;
            }

            Attempt next = new Attempt(realmName, attempt.attempt() + 1, attempt.maxRetries());
            long delayMs = BACKOFF_MULTIPLIER_MS * next.attempt();
            logger.infof("Scheduling registration retry for realm %s in %d ms", realmName, delayMs);
            scheduler.schedule(() -> runRegistrationAttempt(next), delayMs, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Performs one registration attempt for the realm and records its outcome directly in the
     * {@link #registrationStatuses} map: COMPLETED on success, RUNNING when it will be retried
     * (missing key, unhealthy server or failed HTTP call), and entry removal when retry should
     * not be scheduled — realm disabled.
     */
    private void registerRealmAsIssuer(KeycloakSession session, RealmModel realm) {
        String realmName = realm.getName();
        StatusListConfig config = new StatusListConfig(realm);
        if (!config.isEnabled()) {
            // Realm is disabled: drop the entry so a later enablement can register again.
            registrationStatuses.remove(realmName);
            return;
        }

        logger.infof("Starting registration for realm: %s", realmName);
        try (CloseableHttpClient http = registrationClient(config)) {
            StatusListServiceAndKey service = getStatusListService(session, realm, config, http);
            if (service == null) {
                return;
            }

            if (!service.service().checkServerHealth()) {
                logger.warn("Status list server health check failed for realm: " + realmName);
                return;
            }

            service.service().registerIssuer(config.getTokenIssuerId(), service.jwk());
            logger.info("Successfully registered realm as issuer: " + realmName);
            registrationStatuses.put(realmName, RegistrationStatus.COMPLETED);
        } catch (StatusListServerException | StatusListException | IOException e) {
            logger.errorf(e, "Registration failed for realm: %s", realmName);
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

    /**
     * Bundles the status list service facade with the realm's public JWK for issuer registration.
     **/
    private record StatusListServiceAndKey(StatusListService service, JWK jwk) {}

    /**
     * Progress marker threaded through the scheduler:
     * which realm, which attempt no. (counted from 0), within which retry budget.
     */
    public record Attempt(String realmName, int attempt, int maxRetries) {}
}
