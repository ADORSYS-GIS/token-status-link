package com.adorsys.keycloakstatuslist.config;

import org.keycloak.models.KeycloakSession;
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
    private static final boolean DEFAULT_ENABLED = false;
    private static final String DEFAULT_SERVER_URL = "http://localhost:8090/api/v1/token-status";
    private static final String DEFAULT_AUTH_TOKEN = "";
    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DEFAULT_READ_TIMEOUT = 5000;
    private static final int DEFAULT_RETRY_COUNT = 3;

    private final RealmModel realm;

    public StatusListConfig(KeycloakSession session, RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Checks if the status list functionality is enabled for the current realm.
     *
     * @return true if enabled, false otherwise
     */
    public boolean isEnabled() {
        return getBooleanAttribute();
    }

    /**
     * Gets the URL of the status list server.
     *
     * @return the status list server URL
     */
    public String getServerUrl() {
        return getStringAttribute(STATUS_LIST_SERVER_URL, DEFAULT_SERVER_URL);
    }

    /**
     * Gets the authentication token for the status list server.
     *
     * @return the authentication token
     */
    public String getAuthToken() {
        return getStringAttribute(STATUS_LIST_AUTH_TOKEN, DEFAULT_AUTH_TOKEN); 
    }

    /**
     * Gets the connection timeout for the status list server.
     *
     * @return connection timeout in milliseconds
     */
    public int getConnectTimeout() {
        return getIntAttribute(STATUS_LIST_CONNECT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT);
    }

    /**
     * Gets the read timeout for the status list server.
     *
     * @return read timeout in milliseconds
     */
    public int getReadTimeout() {
        return getIntAttribute(STATUS_LIST_READ_TIMEOUT, DEFAULT_READ_TIMEOUT);
    }

    /**
     * Gets the number of retry attempts when communicating with the status list server.
     *
     * @return number of retry attempts
     */
    public int getRetryCount() {
        return getIntAttribute(STATUS_LIST_RETRY_COUNT, DEFAULT_RETRY_COUNT);
    }

    private String getStringAttribute(String name, String defaultValue) {
        String value = realm.getAttribute(name);
        return value != null ? value : defaultValue;
    }

    private boolean getBooleanAttribute() {
        String value = realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED);
        return value != null ? Boolean.parseBoolean(value) : StatusListConfig.DEFAULT_ENABLED;
    }

    private int getIntAttribute(String name, int defaultValue) {
        String value = realm.getAttribute(name);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }
}