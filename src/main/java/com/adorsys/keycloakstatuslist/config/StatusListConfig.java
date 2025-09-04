package com.adorsys.keycloakstatuslist.config;

import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;

import java.util.UUID;

/**
 * Configuration holder for the Token Status plugin.
 * This class provides access to the plugin configuration, which can be set in
 * the Keycloak Admin Console.
 */
@SuppressWarnings("ClassCanBeRecord")
public class StatusListConfig {

    private static final Logger logger = Logger.getLogger(StatusListConfig.class);

    // Configuration keys
    public static final String STATUS_LIST_ENABLED = "status-list-enabled";
    public static final String STATUS_LIST_SERVER_URL = "status-list-server-url";
    public static final String STATUS_LIST_TOKEN_ISSUER_PREFIX = "status-list-token-issuer-prefix";
    public static final String STATUS_LIST_CONNECT_TIMEOUT = "status-list-connect-timeout";
    public static final String STATUS_LIST_READ_TIMEOUT = "status-list-read-timeout";
    public static final String STATUS_LIST_RETRY_COUNT = "status-list-retry-count";

    // Default values
    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_SERVER_URL = "https://statuslist.eudi-adorsys.com/";
    private static final int DEFAULT_CONNECT_TIMEOUT = 30000;
    private static final int DEFAULT_READ_TIMEOUT = 60000;
    private static final int DEFAULT_RETRY_COUNT = 0; // Retry disabled by default

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
            logger.warnf("No token issuer prefix configured for realm %s. Using generated: %s",
                    realm.getName(), prefix);
        }

        return String.format("%s::%s", prefix, realm.getName());
    }

    /**
     * Gets the connection timeout for the status list server.
     *
     * @return connection timeout in milliseconds
     */
    public int getConnectTimeout() {
        String value = realm.getAttribute(STATUS_LIST_CONNECT_TIMEOUT);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return DEFAULT_CONNECT_TIMEOUT;
            }
        }
        return DEFAULT_CONNECT_TIMEOUT;
    }

    /**
     * Gets the read timeout for the status list server.
     *
     * @return read timeout in milliseconds
     */
    public int getReadTimeout() {
        String value = realm.getAttribute(STATUS_LIST_READ_TIMEOUT);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return DEFAULT_READ_TIMEOUT;
            }
        }
        return DEFAULT_READ_TIMEOUT;
    }

    /**
     * Gets the number of retry attempts when communicating with the status list
     * server.
     *
     * @return number of retry attempts
     */
    public int getRetryCount() {
        String value = realm.getAttribute(STATUS_LIST_RETRY_COUNT);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return DEFAULT_RETRY_COUNT;
            }
        }
        return DEFAULT_RETRY_COUNT;
    }
}