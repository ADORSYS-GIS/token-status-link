package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.jboss.logging.Logger;

import java.net.ConnectException;
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
        // Ensure serverUrl ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        logger.debug("Initialized StatusListService with serverUrl: " + this.serverUrl + ", authToken: " + (authToken != null ? "present" : "null"));
    }

    public boolean publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Sending payload to " + serverUrl + "credentials: " + jsonPayload);

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(serverUrl + "credentials"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

            if (authToken != null && !authToken.isEmpty()) {
                requestBuilder.header("Authorization", "Bearer " + authToken);
            }

            HttpRequest request = requestBuilder.build();
            logger.debug("Sending HTTP request: " + request.uri() + ", Headers: " + request.headers());

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();
            String responseBody = response.body();
            String responseHeaders = response.headers().toString();

            logger.debug("Received response: Status code: " + statusCode + ", Headers: " + responseHeaders + ", Body: " + responseBody);

            if (statusCode >= 200 && statusCode < 300) {
                logger.debug("Successfully published record: " + statusRecord.getCredentialId());
                return true;
            } else {
                logger.error("Failed to publish record. Status code: " + statusCode + ", Headers: " + responseHeaders + ", Response body: " + responseBody);
                throw new StatusListServerException(
                        "Failed to publish record. Status code: " + statusCode + ", Response: " + responseBody,
                        statusCode
                );
            }
        } catch (ConnectException e) {
            logger.error("Failed to connect to status list server at " + serverUrl + ": " + e.getMessage(), e);
            throw new StatusListException("Failed to connect to status list server: " + e.getMessage(), e);
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
        if (statusRecord.getStatus() == -1) { // Use -1 to indicate unset status
            statusRecord.setStatus(TokenStatus.VALID);
        }
        if (statusRecord.getIndex() == null) {
            statusRecord.setIndex(0L); // Default index, server may override
        }
        if (statusRecord.getCredentialType() == null || statusRecord.getCredentialType().isEmpty()) {
            statusRecord.setCredentialType("SD-JWT");
        }
        if (statusRecord.getStatus() == TokenStatus.REVOKED.getValue()) {
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