package com.adorsys.keycloakstatuslist.client;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

import com.adorsys.keycloakstatuslist.StatusListProtocolMapper;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * Client for interacting with the status list server directly.
 * This can be used for testing or direct integrations.
 */
public class StatusListClient {

    private static final Logger logger = Logger.getLogger(StatusListClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    private final String serverUrl;
    private final String authToken;
    private final int connectTimeout;
    private final int readTimeout;

    /**
     * Creates a new StatusListClient with default timeouts.
     *
     * @param serverUrl the URL of the status list server
     * @param authToken the authentication token for the server
     */
    public StatusListClient(String serverUrl, String authToken) {
        this(serverUrl, authToken, 5000, 5000);
    }

    /**
     * Creates a new StatusListClient with custom timeouts.
     *
     * @param serverUrl      the URL of the status list server
     * @param authToken      the authentication token for the server
     * @param connectTimeout connection timeout in milliseconds
     * @param readTimeout    read timeout in milliseconds
     */
    public StatusListClient(String serverUrl, String authToken, int connectTimeout, int readTimeout) {
        // Ensure server URL ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    /**
     * Publishes a complete token status record to the server.
     *
     * @param statusRecord the status record to publish
     * @return true if successful, false otherwise
     */
    public boolean publishRecord(TokenStatusRecord statusRecord) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.of(connectTimeout, TimeUnit.MILLISECONDS))
                .setResponseTimeout(Timeout.of(readTimeout, TimeUnit.MILLISECONDS))
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            String endpoint = serverUrl + "credentials";
            HttpPost request = new HttpPost(endpoint);

            request.setHeader("Content-Type", "application/json");
            if (authToken != null && !authToken.isEmpty()) {
                request.setHeader("Authorization", "Bearer " + authToken);
            }

            validateStatusRecord(statusRecord);

            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.info("Sending payload: " + jsonPayload);
            request.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getCode();
                logger.info("Status code: " + statusCode);

                if (statusCode < 200 || statusCode >= 300) {
                    try {
                        String responseBody = new String(response.getEntity().getContent().readAllBytes());
                        logger.warn("Response body: " + responseBody);
                    } catch (Exception e) {
                        logger.warn("Could not read response body: " + e.getMessage());
                    }
                }

                return statusCode >= 200 && statusCode < 300;
            }
        } catch (IOException e) {
            logger.error("Error publishing record", e);
            return false;
        }
    }

    /**
     * Validates that all required fields are set in the status record according to
     * OAuth Status List spec.
     *
     * @param statusRecord The record to validate
     */
    private void validateStatusRecord(TokenStatusRecord statusRecord) {
        Instant now = Instant.now();

        // Ensure credentialId is set (sub claim)
        if (statusRecord.getCredentialId() == null || statusRecord.getCredentialId().isEmpty()) {
            throw new IllegalArgumentException("Credential ID (sub) is required");
        }

        // Ensure issuerId is set (iss claim)
        if (statusRecord.getIssuerId() == null || statusRecord.getIssuerId().isEmpty()) {
            throw new IllegalArgumentException("Issuer ID (iss) is required");
        }

        // Ensure status is set
        if (statusRecord.getStatus() == -1) {
            statusRecord.setStatus(TokenStatus.VALID);
        }

        // Ensure issuedAt is set
        if (statusRecord.getIssuedAt() == null) {
            statusRecord.setIssuedAt(now);
        }

        // Ensure expiresAt is set
        if (statusRecord.getExpiresAt() == null) {
            statusRecord.setExpiresAt(now.plusSeconds(3600)); // 1 hour
        }

        // For revoked tokens, ensure revokedAt and statusReason are set
        if (statusRecord.getStatus() == TokenStatus.REVOKED.getValue()) {
            if (statusRecord.getRevokedAt() == null) {
                statusRecord.setRevokedAt(now);
            }
            if (statusRecord.getStatusReason() == null || statusRecord.getStatusReason().isEmpty()) {
                statusRecord.setStatusReason("Token revoked");
            }
        }

        // Ensure credentialType is set - use "oauth2" as per the spec
        if (statusRecord.getCredentialType() == null || statusRecord.getCredentialType().isEmpty()) {
            statusRecord.setCredentialType("oauth2");
        }
    }
}