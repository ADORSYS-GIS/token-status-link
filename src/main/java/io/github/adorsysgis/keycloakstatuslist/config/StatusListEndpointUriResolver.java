package io.github.adorsysgis.keycloakstatuslist.config;

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

    private final String serverUrl;

    /**
     * Creates a resolver for the given status-list server base URL.
     *
     * @param serverUrl the status-list server URL (trailing slash is normalised automatically)
     */
    public StatusListEndpointUriResolver(String serverUrl) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
    }

    /**
     * Returns the normalised base server URL.
     */
    public String getServerUrl() {
        return serverUrl;
    }

    /**
     * Full URL for credential issuer registration.
     * <p>Example: {@code https://example.com/api/v1/credentials}</p>
     */
    public String credentialsUrl() {
        return serverUrl + CREDENTIALS_PATH;
    }

    /**
     * Full URL to retrieve or check a specific status list.
     * <p>Example: {@code https://example.com/api/v1/status-lists/{listId}}</p>
     */
    public String statusListUrl(String listId) {
        return serverUrl + STATUS_LISTS_PATH + "/" + listId;
    }

    /**
     * Full URL to publish or update status entries of a specific status list.
     * <p>Example: {@code https://example.com/api/v1/status-lists/{listId}/statuses}</p>
     */
    public String statusListStatusesUrl(String listId) {
        return statusListUrl(listId) + "/" + STATUSES_SUB_PATH;
    }

    /**
     * Full URL for the server health-check endpoint.
     * <p>Example: {@code https://example.com/health}</p>
     */
    public String healthUrl() {
        return serverUrl + HEALTH_PATH;
    }

    /**
     * URI path segment for retrieving a specific status list.
     * The path starts with a leading slash so it can be used directly
     * with {@link UriBuilder#path(String)}.
     * <p>Example: {@code /api/v1/status-lists/{listId}}</p>
     *
     * @param listId the status list identifier
     * @return the path segment (leading slash included)
     */
    public String statusListRetrievePath(String listId) {
        return "/" + STATUS_LISTS_PATH + "/" + listId;
    }
}
