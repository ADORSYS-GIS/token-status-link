package com.adorsys.keycloakstatuslist.client;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.jboss.logging.Logger;

/**
 * Client for interacting with the status list server directly.
 * This can be used for testing or direct integrations.
 */
public class StatusListClient {

    private static final Logger logger = Logger.getLogger(StatusListClient.class);

    private final StatusListService statusListService;

    public StatusListClient(String serverUrl, String authToken) {
        // For direct client usage, use default timeouts and no circuit breaker
        StatusListHttpClient httpClient = new ApacheHttpStatusListClient(
                serverUrl,
                authToken,
                CustomHttpClient.getHttpClient(),
                null
        );
        this.statusListService = new StatusListService(httpClient);
    }

    public StatusListClient(StatusListService statusListService) {
        this.statusListService = statusListService;
    }

    /**
     * Publishes a complete token status record to the server.
     *
     * @param statusRecord the status record to publish
     * @return true if successful, false otherwise
     */
    public boolean publishRecord(TokenStatusRecord statusRecord) {
        // Basic validation for backward compatibility with tests
        validateBasicFields(statusRecord);
        
        try {
            statusListService.publishRecord(statusRecord);
            return true;
        } catch (StatusListException e) {
            logger.error("Error publishing record", e);
            return false;
        }
    }

    /**
     * Basic validation for backward compatibility with existing tests.
     * This ensures the tests that expect IllegalArgumentException still work.
     */
    private void validateBasicFields(TokenStatusRecord statusRecord) {
        if (statusRecord.getCredentialId() == null || statusRecord.getCredentialId().isEmpty()) {
            throw new IllegalArgumentException("Credential ID (sub) is required");
        }
        if (statusRecord.getIssuerId() == null || statusRecord.getIssuerId().isEmpty()) {
            throw new IllegalArgumentException("Issuer ID (iss) is required");
        }
    }

}