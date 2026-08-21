package io.github.adorsysgis.keycloakstatuslist.config;

import jakarta.ws.rs.core.UriBuilder;

/**
 * Centralised resolver for all status-list server endpoint URIs.
 * <p>
 * Every path fragment lives here exactly once so that a future API-version
 * bump or path rename only needs a single edit.
 */
public final class StatusListEndpointUriResolver {

    private static final String API_V1_PATH = "api/v1";
    private static final String CREDENTIALS_PATH = API_V1_PATH + "/credentials";
    private static final String STATUS_LISTS_PATH = API_V1_PATH + "/status-lists";
    private static final String STATUSES_SUB_PATH = "statuses";
    private static final String HEALTH_PATH = "health";

    private final UriBuilder baseUriBuilder;

    /**
     * Creates a resolver for the given status-list server base URL.
     *
     * @param serverUrl the status-list server URL
     */
    public StatusListEndpointUriResolver(String serverUrl) {
        this.baseUriBuilder = UriBuilder.fromUri(serverUrl);
    }

    /**
     * Returns the base server URL.
     */
    public String getServerUrl() {
        return baseUriBuilder.clone().build().toString();
    }

    /**
     * Full URL for credential issuer registration.
     */
    public String credentialsUrl() {
        return baseUriBuilder.clone().path(CREDENTIALS_PATH).build().toString();
    }

    /**
     * Full URL to retrieve or check a specific status list.
     */
    public String statusListUrl(String listId) {
        return baseUriBuilder
                .clone()
                .path(STATUS_LISTS_PATH)
                .path("{listId}")
                .build(listId)
                .toString();
    }

    /**
     * Full URL to publish or update status entries of a specific status list.
     */
    public String statusListStatusesUrl(String listId) {
        return statusListUrl(listId) + "/" + STATUSES_SUB_PATH;
    }

    /**
     * Full URL for the server health-check endpoint.
     */
    public String healthUrl() {
        return baseUriBuilder.clone().path(HEALTH_PATH).build().toString();
    }
}
