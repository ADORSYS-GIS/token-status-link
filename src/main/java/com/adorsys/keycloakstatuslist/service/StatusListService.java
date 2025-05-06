package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Instant;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private final String serverUrl;
    private final String authToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public StatusListService(String serverUrl, String authToken) {
        this.serverUrl = serverUrl;
        this.authToken = authToken;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public boolean publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Sending payload: " + jsonPayload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl + "/credentials"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + authToken)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();

            if (statusCode >= 200 && statusCode < 300) {
                logger.debug("Successfully published record: " + statusRecord.getCredentialId());
                return true;
            } else {
                String responseBody = response.body();
                logger.error("Request failed. Status code: " + statusCode + ", Response: " + responseBody);
                throw new StatusListServerException(
                        "Request failed. Status code: " + statusCode + ", Response: " + responseBody,
                        statusCode
                );
            }
        } catch (Exception e) {
            logger.error("Failed to publish record: " + e.getMessage(), e);
            throw new StatusListException("Failed to publish record: " + e.getMessage(), e);
        }
    }

    private void validateStatusRecord(TokenStatusRecord statusRecord) throws StatusListException {
        if (statusRecord.getCredentialId() == null || statusRecord.getCredentialId().isEmpty()) {
            throw new StatusListException("Credential ID is required");
        }
        if (statusRecord.getIssuerId() == null || statusRecord.getIssuerId().isEmpty()) {
            throw new StatusListException("Issuer ID is required");
        }
        if (statusRecord.getStatus() == null) {
            throw new StatusListException("Status is required");
        }
        if (statusRecord.getCredentialType() == null || statusRecord.getCredentialType().isEmpty()) {
            statusRecord.setCredentialType("SD-JWT");
        }
        if (statusRecord.getStatus() == TokenStatus.REVOKED) {
            if (statusRecord.getRevokedAt() == null) {
                statusRecord.setRevokedAt(Instant.now());
            }
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("Token revoked");
            }
        }
        if (statusRecord.getIssuedAt() == null) {
            statusRecord.setIssuedAt(Instant.now());
        }
        if (statusRecord.getExpiresAt() == null) {
            statusRecord.setExpiresAt(Instant.now().plusSeconds(3600));
        }
    }
}

class StatusListException extends Exception {
    public StatusListException(String message) {
        super(message);
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}

class StatusListServerException extends StatusListException {
    private final int statusCode;

    public StatusListServerException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}