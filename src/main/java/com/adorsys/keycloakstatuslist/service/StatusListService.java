package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;

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
                doUpdateStatusList(payload, requestId);
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

    private void doUpdateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        httpClient.updateStatusList(payload, requestId);
    }

    /**
     * Updates an existing status list on the server. Used by revocation flow.
     *
     * @param payload   the status list payload
     * @param requestId correlation ID for tracking
     * @throws StatusListException if the operation fails
     */
    public void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        doUpdateStatusList(payload, requestId);
    }

    /**
     * Checks the health status of the status list server.
     *
     * @return true if the server is healthy, false otherwise
     */
    public boolean checkServerHealth() {
        return httpClient.checkServerHealth();
    }

    /**
     * Gets the URI for a status list without making any HTTP calls.
     *
     * @param listId the status list identifier
     * @return the URI string for the status list
     */
    public String getStatusListUri(String listId) {
        return httpClient.getStatusListUri(listId);
    }

    /**
     * Registers a status entry and publishes it to the server.
     *
     * @param listId the status list identifier
     * @param index the index of the token in the status list
     * @return Status object containing the index and URI
     * @throws StatusListException if the operation fails
     */
    public Status registerAndPublishStatus(String listId, long index) throws StatusListException {
        // Prepare payload
        StatusListPayload payload = new StatusListPayload(
                listId,
                List.of(new StatusListPayload.StatusEntry((int) index, "VALID")));
        
        publishOrUpdate(payload);
        
        String uri = httpClient.getStatusListUri(listId);
        
        // Return Status with index and URI
        StatusListClaim statusList = new StatusListClaim(index, uri);
        return new Status(statusList);
    }

    public record StatusListPayload(
            @JsonProperty("list_id") String listId,
            List<StatusEntry> status) {
        public record StatusEntry(long index, String status) {
        }
    }
}
