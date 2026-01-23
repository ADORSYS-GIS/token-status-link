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
    public static final String STATUS_LIST_ISSUANCE_CONNECT_TIMEOUT = "status-list-issuance-connect-timeout";
    public static final String STATUS_LIST_ISSUANCE_READ_TIMEOUT = "status-list-issuance-read-timeout";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_ENABLED = "status-list-circuit-breaker-enabled";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD = "status-list-circuit-breaker-failure-threshold";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_TIMEOUT_THRESHOLD = "status-list-circuit-breaker-timeout-threshold";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_WINDOW_SECONDS = "status-list-circuit-breaker-window-seconds";
    public static final String STATUS_LIST_CIRCUIT_BREAKER_COOLDOWN_SECONDS = "status-list-circuit-breaker-cooldown-seconds";
    public static final String STATUS_LIST_MANDATORY = "status-list-mandatory";
   
    // Default values
    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_SERVER_URL = "https://statuslist.eudi-adorsys.com/";
    
    // Default timeout values for issuance path (shorter than general operations)
    private static final int DEFAULT_ISSUANCE_CONNECT_TIMEOUT = 5000;
    private static final int DEFAULT_ISSUANCE_READ_TIMEOUT = 10000;
    
    // Default circuit breaker values
    private static final boolean DEFAULT_CIRCUIT_BREAKER_ENABLED = true;
    private static final int DEFAULT_FAILURE_THRESHOLD = 5;
    private static final int DEFAULT_TIMEOUT_THRESHOLD = 3;
    private static final int DEFAULT_WINDOW_SECONDS = 60;
    private static final int DEFAULT_COOLDOWN_SECONDS = 30;
    private static final boolean DEFAULT_MANDATORY = false;

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
                    "No token issuer prefix configured for realm %s. Using generated: %s",
                    realm.getName(), prefix);
        }

        return String.format("%s::%s", prefix, realm.getName());
    }

    /**
     * Gets the connection timeout for issuance operations in milliseconds.
     *
     * @return the connect timeout in milliseconds
     */
    public int getIssuanceConnectTimeout() {
        String value = realm.getAttribute(STATUS_LIST_ISSUANCE_CONNECT_TIMEOUT);
        return value != null ? Integer.parseInt(value) : DEFAULT_ISSUANCE_CONNECT_TIMEOUT;
    }

    /**
     * Gets the read timeout for issuance operations in milliseconds.
     *
     * @return the read timeout in milliseconds
     */
    public int getIssuanceReadTimeout() {
        String value = realm.getAttribute(STATUS_LIST_ISSUANCE_READ_TIMEOUT);
        return value != null ? Integer.parseInt(value) : DEFAULT_ISSUANCE_READ_TIMEOUT;
    }

    /**
     * Checks if the circuit breaker is enabled.
     *
     * @return true if circuit breaker is enabled, false otherwise
     */
    public boolean isCircuitBreakerEnabled() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_ENABLED);
        return value != null ? Boolean.parseBoolean(value) : DEFAULT_CIRCUIT_BREAKER_ENABLED;
    }

    /**
     * Gets the failure threshold for the circuit breaker.
     *
     * @return the number of failures before opening the circuit
     */
    public int getCircuitBreakerFailureThreshold() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_FAILURE_THRESHOLD);
        return value != null ? Integer.parseInt(value) : DEFAULT_FAILURE_THRESHOLD;
    }

    /**
     * Gets the timeout threshold for the circuit breaker.
     *
     * @return the number of timeouts before considering as failure
     */
    public int getCircuitBreakerTimeoutThreshold() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_TIMEOUT_THRESHOLD);
        return value != null ? Integer.parseInt(value) : DEFAULT_TIMEOUT_THRESHOLD;
    }

    /**
     * Gets the time window in seconds for tracking failures.
     *
     * @return the rolling window size in seconds
     */
    public int getCircuitBreakerWindowSeconds() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_WINDOW_SECONDS);
        return value != null ? Integer.parseInt(value) : DEFAULT_WINDOW_SECONDS;
    }

    /**
     * Gets the cooldown period in seconds before attempting recovery.
     *
     * @return the cooldown period in seconds
     */
    public int getCircuitBreakerCooldownSeconds() {
        String value = realm.getAttribute(STATUS_LIST_CIRCUIT_BREAKER_COOLDOWN_SECONDS);
        return value != null ? Integer.parseInt(value) : DEFAULT_COOLDOWN_SECONDS;
    }

}
