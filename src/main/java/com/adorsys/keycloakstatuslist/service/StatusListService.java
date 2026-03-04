package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;

import java.util.List;
import java.util.UUID;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);

    private final StatusListHttpClient httpClient;

    /**
     * Creates a new StatusListService with the provided HTTP client.
     *
     * @param httpClient the HTTP client implementation to use
     */
    public StatusListService(StatusListHttpClient httpClient) {
        this.httpClient = httpClient;
        logger.info("Initialized StatusListService with HTTP client: " + httpClient.getClass().getSimpleName());
    }

    /**
     * Factory method to create a StatusListService instance for the given Keycloak session.
     * Handles configuration, circuit breaker creation, and HTTP client setup.
     *
     * @param session the Keycloak session
     * @return a configured StatusListService instance
     */
    public static StatusListService create(KeycloakSession session) {
        StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
        CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
        String realmId = session.getContext().getRealm().getId();

        // Create circuit breaker if timeout is positive (non-positive timeout disables circuit breaker)
        CircuitBreaker circuitBreaker = null;
        if (config.getIssuanceTimeout() > 0) {
            int threshold = config.getCircuitBreakerFailureThreshold();
            circuitBreaker = CircuitBreaker.getInstanceForRealm(realmId, "StatusList",
                    threshold,
                    config.getCircuitBreakerWindowSeconds(),
                    config.getCircuitBreakerCooldownSeconds());
        }

        // Create HTTP client with custom timeout for issuance path
        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                config.getServerUrl(),
                cryptoIdentityService.getJwtToken(config),
                CustomHttpClient.getHttpClient(config),
                circuitBreaker
        );

        return new StatusListService(httpClient);
    }

    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        httpClient.registerIssuer(issuerId, publicKey);
    }

    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        return httpClient.checkStatusListExists(statusListId);
    }

    public void publishOrUpdate(StatusListPayload payload) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        String listId = payload.listId();

        try {
            boolean exists = checkStatusListExists(listId);
            if (exists) {
                updateStatusList(payload, requestId);
            } else {
                publishStatusList(payload, requestId);
            }
        } catch (StatusListException e) {
            logger.errorf(
                    "Request ID: %s, Failed to publish or update status list %s: %s",
                    requestId,
                    listId,
                    e.getMessage(),
                    e);
            throw e;
        }
    }

    private void publishStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        httpClient.publishStatusList(payload, requestId);
    }

    /**
     * Updates an existing status list on the server. Used by revocation flow.
     *
     * @param payload   the status list payload
     * @param requestId correlation ID for tracking
     * @throws StatusListException if the operation fails
     */
    public void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        httpClient.updateStatusList(payload, requestId);
    }

    /**
     * Checks the health status of the status list server.
     *
     * @return true if the server is healthy, false otherwise
     */
    public boolean checkServerHealth() {
        return httpClient.checkServerHealth();
    }

    private static final String STATUS_LISTS_PATH = "statuslists";
    
    /**
     * Gets the URI for a status list without making any HTTP calls.
     *
     * @param listId the status list identifier
     * @return the URI string for the status list
     */
    public String getStatusListUri(String listId) {
        String serverUrl = httpClient.getServerUrl();
        return serverUrl + STATUS_LISTS_PATH + "/" + listId;
    }

    public record StatusListPayload(
            @JsonProperty("list_id") String listId,
            List<StatusEntry> status) {
        public record StatusEntry(long index, String status) {
        }
    }
}
