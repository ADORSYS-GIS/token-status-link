package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);

    private final String serverUrl;
    private final String authToken;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public StatusListService(String serverUrl, String authToken, CloseableHttpClient httpClient) {
        // Ensure serverUrl ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        logger.info("Initialized StatusListService with serverUrl: " + this.serverUrl);
    }

    public void publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        String requestId = UUID.randomUUID().toString(); // Correlation ID for tracing
        String credentialId = statusRecord.getCredentialId(); // For logging context

        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Request ID: " + requestId + ", Publishing record for credentialId: " + credentialId);

            HttpPost httpPost = new HttpPost(serverUrl + "credentials");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            if (authToken != null && !authToken.isEmpty()) {
                httpPost.setHeader("Authorization", "Bearer " + authToken);
            }

            logger.debug("Request ID: " + requestId + ", Sending HTTP request to: " + httpPost.getUri());

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully published record for credentialId: "
                            + credentialId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    return null; // Success, handler returns null
                } else {
                    logger.error("Request ID: " + requestId + ", Failed to publish record for credentialId: "
                            + credentialId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to publish record for credentialId: " + credentialId + ". Status code: "
                                    + statusCode,
                            statusCode));
                }
            });

        } catch (IOException e) {
            logger.error("Request ID: " + requestId + ", Failed to publish record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Failed to publish record for credentialId: " + credentialId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            logger.error("Request ID: " + requestId + ", Unexpected error publishing record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error publishing record for credentialId: " + credentialId, e);
        }
    }


    public void registerIssuer(String issuerId, String publicKey, String algorithm) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        logger.info("Request ID: " + requestId + ", Registering issuer: " + issuerId + " with server: " + serverUrl);

        // Create a simple record with just the required fields for issuer registration
        TokenStatusRecord issuerRecord = new TokenStatusRecord();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);
        issuerRecord.setAlg(algorithm);

        try {
            String jsonPayload = objectMapper.writeValueAsString(issuerRecord);
            logger.debug("Request ID: " + requestId + ", Registering issuer: " + issuerId + ", Payload: " + jsonPayload);

            HttpPost httpPost = new HttpPost(serverUrl + "credentials");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                String responseHeaders = response.getHeaders().toString();

                logger.debug("Request ID: " + requestId + ", Received response: Status code: " + statusCode +
                        ", Headers: " + responseHeaders + ", Body: " + responseBody);

                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully registered issuer: " + issuerId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    return Boolean.TRUE; // Success
                } else {
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to register issuer: " + issuerId +
                                    ", Status code: " + statusCode +
                                    ", Response: " + responseBody,
                            statusCode));
                }
            });
        } catch (IOException e) {
            logger.error("Request ID: " + requestId + ", Failed to register issuer: " + issuerId +
                    ": " + e.getMessage() + ", Server URL: " + serverUrl, e);
            throw new StatusListException("Failed to register issuer: " + issuerId +
                    ", Server URL: " + serverUrl, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            logger.error("Request ID: " + requestId + ", Unexpected error registering issuer: " + issuerId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error registering issuer: " + issuerId, e);
        }
    }

    private void validateStatusRecord(TokenStatusRecord statusRecord) throws StatusListException {
        String credentialId = statusRecord.getCredentialId() != null ? statusRecord.getCredentialId() : "unknown";

        // Check required fields according to the specification
        if (statusRecord.getCredentialId() == null || statusRecord.getCredentialId().isEmpty()) {
            throw new StatusListException("Credential ID (sub) is required for credentialId: " + credentialId);
        }

        // Ensure both iss and issuer fields are set
        if (statusRecord.getIssuerId() == null || statusRecord.getIssuerId().isEmpty()) {
            throw new StatusListException("Issuer ID (iss) is required for credentialId: " + credentialId);
        }

        // Make sure issuer field is set if not already
        if (statusRecord.getIssuer() == null || statusRecord.getIssuer().isEmpty()) {
            statusRecord.setIssuer(statusRecord.getIssuerId());
        }

        // Require public_key to be set by the caller (e.g.,
        // TokenStatusEventListenerProvider)
        if (statusRecord.getPublicKey() == null || statusRecord.getPublicKey().isEmpty()) {
            throw new StatusListException(
                    "Public key is required and must be retrieved from Keycloak's KeyManager for credentialId: "
                            + credentialId);
        }

        // Require alg to be set by the caller
        if (statusRecord.getAlg() == null || statusRecord.getAlg().isEmpty()) {
            throw new StatusListException(
                    "Algorithm (alg) is required and must be retrieved from Keycloak's KeyManager for credentialId: "
                            + credentialId);
        }

        if (statusRecord.getStatus() == -1) {
            statusRecord.setStatus(TokenStatus.VALID);
        }

        // Optional fields that should be null if not explicitly set
        if (statusRecord.getIndex() != null && statusRecord.getIndex() == 0L) {
            statusRecord.setIndex(null);
        }

        if (statusRecord.getCredentialType() == null || statusRecord.getCredentialType().isEmpty()) {
            statusRecord.setCredentialType("oauth2");
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