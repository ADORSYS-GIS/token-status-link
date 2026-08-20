package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.client.StatusListHttpClient;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListServerException;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import java.util.List;
import java.util.UUID;
import org.apache.hc.core5.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;

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
        logger.info("Initialized StatusListService with HTTP client: "
                + httpClient.getClass().getSimpleName());
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
            publishStatusList(payload, requestId);
        } catch (StatusListServerException e) {
            if (e.getStatusCode() == HttpStatus.SC_CONFLICT) {
                logger.infof(
                        "Request ID: %s, Status list %s already exists; updating existing list", requestId, listId);
                updateStatusList(payload, requestId);
                return;
            }
            logPublishOrUpdateFailure(requestId, listId, e);
            throw e;
        } catch (StatusListException e) {
            logPublishOrUpdateFailure(requestId, listId, e);
            throw e;
        }
    }

    private void logPublishOrUpdateFailure(String requestId, String listId, Exception e) {
        logger.errorf(
                "Request ID: %s, Failed to publish or update status list %s: %s", requestId, listId, e.getMessage(), e);
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

    public record StatusListPayload(String listId, List<StatusEntry> status) {
        public record StatusEntry(long index, TokenStatus status) {}
    }
}
