package com.adorsys.keycloakstatuslist.config;

import org.keycloak.models.RealmModel;

/**
 * Configuration holder for the Token Status plugin.
 * This class provides access to the plugin configuration, which can be set in the Keycloak Admin Console.
 */
public class StatusListConfig {

    // Configuration keys
    public static final String STATUS_LIST_ENABLED = "status-list-enabled";
    public static final String STATUS_LIST_SERVER_URL = "status-list-server-url";
    public static final String STATUS_LIST_AUTH_TOKEN = "status-list-auth-token";
    public static final String STATUS_LIST_CONNECT_TIMEOUT = "status-list-connect-timeout";
    public static final String STATUS_LIST_READ_TIMEOUT = "status-list-read-timeout";
    public static final String STATUS_LIST_RETRY_COUNT = "status-list-retry-count";

    // Default values
    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_SERVER_URL = "http://localhost:8080/";
    private static final String DEFAULT_AUTH_TOKEN = "";
    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DEFAULT_READ_TIMEOUT = 5000;
    private static final int DEFAULT_RETRY_COUNT = 3;

    private final RealmModel realm;

    public StatusListConfig(RealmModel realm) {
        this.realm = realm;
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
     * Gets the authentication token for the status list server.
     *
     * @return the authentication token
     */
    public String getAuthToken() {
        String value = realm.getAttribute(STATUS_LIST_AUTH_TOKEN);
        return value != null ? value : DEFAULT_AUTH_TOKEN;
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
     * Gets the number of retry attempts when communicating with the status list server.
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