package com.adorsys.keycloakstatuslist.config;

import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

/**
 * Configuration holder for the Token Status plugin. This class provides access to the plugin
 * configuration, which can be set in the Keycloak Admin Console.
 */
@SuppressWarnings("ClassCanBeRecord")
public class StatusListConfig {

    private static final Logger logger = Logger.getLogger(StatusListConfig.class);

    // Configuration keys
    public static final String STATUS_LIST_ENABLED = "status-list-enabled";
    public static final String STATUS_LIST_SERVER_URL = "status-list-server-url";
    public static final String STATUS_LIST_TOKEN_ISSUER_PREFIX = "status-list-token-issuer-prefix";
    public static final String STATUS_LIST_ISSUANCE_TIMEOUT = "status-list-issuance-timeout";
    public static final String STATUS_LIST_REGISTRATION_TIMEOUT = "status-list-registration-timeout";
    public static final String STATUS_LIST_REGISTRATION_RETRIES = "status-list-registration-retries";
    public static final String STATUS_LIST_REGISTRATION_COOLDOWN = "status-list-registration-cooldown";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD =
            "status-list-circuit-breaker-failure-threshold";
    public static final String STATUS_LIST_MANDATORY = "status-list-mandatory";
    public static final String STATUS_LIST_MAX_ENTRIES = "status-list-max-entries";

    // Default values
    public static final boolean DEFAULT_ENABLED = true;
    public static final String DEFAULT_SERVER_URL = "https://statuslist.eudi-adorsys.com/";
    public static final boolean DEFAULT_MANDATORY = false;
    public static final int DEFAULT_MAX_ENTRIES = 10000;

    // Default values for issuance path (runtime)
    private static final int DEFAULT_ISSUANCE_TIMEOUT = 10000;

    // Default values for registration path (background)
    private static final int DEFAULT_REGISTRATION_TIMEOUT = 30000;
    private static final int DEFAULT_REGISTRATION_RETRIES = 1;
    private static final int DEFAULT_REGISTRATION_COOLDOWN_SECONDS = 60;

    // Default circuit breaker values
    private static final int DEFAULT_FAILURE_THRESHOLD = 5;
    private static final int DEFAULT_WINDOW_SECONDS = 60;
    private static final int DEFAULT_COOLDOWN_SECONDS = 30;

    private final RealmModel realm;

    public StatusListConfig(RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Gets the realm associated with this configuration.
     */
    public RealmModel getRealm() {
        return realm;
    }

    /**
     * Gets the realm ID. Convenience for components that need the realm identifier (e.g. circuit breaker keying).
     *
     * @return the realm identifier
     */
    public String getRealmId() {
        return realm.getId();
    }

    /**
     * Checks if the status list functionality is enabled for the current realm.
     *
     * @return true if enabled, false otherwise
     */
    public boolean isEnabled() {
        String value = realm.getAttribute(STATUS_LIST_ENABLED);
        return value != null ? Boolean.parseBoolean(value) : DEFAULT_ENABLED;
    }

    public boolean isMandatory() {
        String value = realm.getAttribute(STATUS_LIST_MANDATORY);
        return value != null ? Boolean.parseBoolean(value) : DEFAULT_MANDATORY;
    }

    /**
     * Gets the URL of the status list server.
     *
     * @return the status list server URL
     */
    public String getServerUrl() {
        String value = realm.getAttribute(STATUS_LIST_SERVER_URL);
        return value != null ? value : DEFAULT_SERVER_URL;
    }

    /**
     * Gets the Token Issuer ID for the current realm.
     *
     * @return the token issuer ID
     */
    public String getTokenIssuerId() {
        String prefix = realm.getAttribute(STATUS_LIST_TOKEN_ISSUER_PREFIX);
        if (prefix == null) {
            prefix = UUID.randomUUID().toString();
            realm.setAttribute(STATUS_LIST_TOKEN_ISSUER_PREFIX, prefix);
            logger.warnf(
                    "No token issuer prefix configured for realm %s. Using generated: %s", realm.getName(), prefix);
        }

        return String.format("%s::%s", prefix, realm.getName());
    }

    /**
     * Gets the timeout for issuance operations in milliseconds.
     * This timeout is used for both connection and read operations.
     * If the value is non-positive, the circuit breaker will effectively be disabled.
     *
     * @return the timeout in milliseconds
     */
    public int getIssuanceTimeout() {
        String value = realm.getAttribute(STATUS_LIST_ISSUANCE_TIMEOUT);
        return value != null ? Integer.parseInt(value) : DEFAULT_ISSUANCE_TIMEOUT;
    }

    /**
     * Gets the timeout for background registration operations in milliseconds.
     *
     * @return the timeout in milliseconds
     */
    public int getRegistrationTimeout() {
        String value = realm.getAttribute(STATUS_LIST_REGISTRATION_TIMEOUT);
        return value != null ? Integer.parseInt(value) : DEFAULT_REGISTRATION_TIMEOUT;
    }

    /**
     * Gets the number of retries for background registration operations.
     *
     * @return the maximum number of retries
     */
    public int getRegistrationRetries() {
        String value = realm.getAttribute(STATUS_LIST_REGISTRATION_RETRIES);
        return value != null ? Integer.parseInt(value) : DEFAULT_REGISTRATION_RETRIES;
    }

    /**
     * Gets the cooldown period in milliseconds between registration attempts for the same realm.
     *
     * @return the cooldown period in milliseconds
     */
    public long getRegistrationCooldownMs() {
        String value = realm.getAttribute(STATUS_LIST_REGISTRATION_COOLDOWN);
        int seconds = value != null ? Integer.parseInt(value) : DEFAULT_REGISTRATION_COOLDOWN_SECONDS;
        return seconds * 1000L;
    }

    /**
     * Gets the failure threshold for the circuit breaker.
     * This threshold applies to both failures and timeouts.
     *
     * @return the number of failures/timeouts before opening the circuit
     */
    public int getCircuitBreakerFailureThreshold() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD);
        return value != null ? Integer.parseInt(value) : DEFAULT_FAILURE_THRESHOLD;
    }

    /**
     * Gets the time window in seconds for tracking failures.
     *
     * @return the rolling window size in seconds
     */
    public int getCircuitBreakerWindowSeconds() {
        return DEFAULT_WINDOW_SECONDS;
    }

    /**
     * Gets the cooldown period in seconds before attempting recovery.
     *
     * @return the cooldown period in seconds
     */
    public int getCircuitBreakerCooldownSeconds() {
        return DEFAULT_COOLDOWN_SECONDS;
    }

    /**
     * Gets the maximum number of entries allowed under the same status list.
     *
     * @return the maximum number of entries
     */
    public int getStatusListMaxEntries() {
        String value = realm.getAttribute(STATUS_LIST_MAX_ENTRIES);
        if (value == null) {
            logger.warnf(
                    "No max entries value configured for realm %s. Using default: %d",
                    realm.getName(), DEFAULT_MAX_ENTRIES);
            return DEFAULT_MAX_ENTRIES;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            logger.warnf(
                    "Invalid max entries value '%s' for realm %s. Using default: %d",
                    value, realm.getName(), DEFAULT_MAX_ENTRIES);
            return DEFAULT_MAX_ENTRIES;
        }
    }
}
