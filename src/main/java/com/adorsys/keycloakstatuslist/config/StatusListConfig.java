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
    public static final String STATUS_LIST_MANDATORY = "status-list-mandatory";
    public static final String STATUS_LIST_MAX_ENTRIES = "status-list-max-entries";

    // Default values
    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_SERVER_URL = "https://statuslist.eudi-adorsys.com/";
    private static final boolean DEFAULT_MANDATORY = false;
    private static final int DEFAULT_MAX_ENTRIES = 10000;

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
