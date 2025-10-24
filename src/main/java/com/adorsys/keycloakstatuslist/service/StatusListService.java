package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Instant;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private final String serverUrl;
    private final String authToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final int retryCount;

    public StatusListService(String serverUrl, String authToken) {
        this(serverUrl, authToken, 5000, 5000, 3);
    }

    public StatusListService(String serverUrl, String authToken, int connectTimeout, int readTimeout, int retryCount) {
        this(serverUrl, authToken, createDefaultHttpClient(connectTimeout), retryCount);
    }

    public StatusListService(String serverUrl, String authToken, HttpClient httpClient, int retryCount) {
        // Ensure serverUrl ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.retryCount = Math.max(0, retryCount); // Ensure non-negative retry count
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        logger.info(
                "Initialized StatusListService with serverUrl: " + this.serverUrl + ", retryCount: " + this.retryCount);
    }

    private static HttpClient createDefaultHttpClient(int connectTimeout) {
        try {
            // Configure HttpClient with secure TLS settings
            SSLContext sslContext = SSLContext.getDefault();
            SSLParameters sslParameters = new SSLParameters();
            sslParameters.setProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .sslParameters(sslParameters)
                    .connectTimeout(Duration.ofMillis(connectTimeout))
                    .build();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to initialize SSLContext for HttpClient", e);
            throw new IllegalStateException("Cannot initialize secure HttpClient", e);
        }
    }

    public void publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        String requestId = UUID.randomUUID().toString(); // Correlation ID for tracing
        String credentialId = statusRecord.getCredentialId(); // For logging context

        String jsonPayload;
        try {
            jsonPayload = objectMapper.writeValueAsString(statusRecord);
        } catch (JsonProcessingException e) {
            logger.error("Request ID: " + requestId + ", Failed to serialize status record for credentialId: "
                    + credentialId, e);
            throw new StatusListException("Failed to serialize status record for credentialId: " + credentialId, e);
        }

        HttpRequest.Builder requestBuilder = buildBaseRequest(requestId, "credentials")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

        executeRequestWithRetry(requestBuilder, requestId, credentialId, "publish record");
    }

    private HttpRequest.Builder buildBaseRequest(String requestId, String path) {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + path))
                .header("Content-Type", "application/json")
                .header("X-Request-ID", requestId)
                .timeout(Duration.ofSeconds(30));

        if (authToken != null && !authToken.isEmpty()) {
            requestBuilder.header("Authorization", "Bearer " + authToken);
        }
        return requestBuilder;
    }

    private HttpResponse<String> executeRequestWithRetry(HttpRequest.Builder requestBuilder, String requestId,
            String entityId, String operation) throws StatusListException {
        for (int attempt = 1; attempt <= retryCount + 1; attempt++) {
            try {
                HttpRequest request = requestBuilder.build();
                logger.debug("Request ID: " + requestId + ", Attempt: " + attempt + ", Sending HTTP request for "
                        + operation + " to: " + request.uri());

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                int statusCode = response.statusCode();
                String responseBody = response.body();
                String responseHeaders = response.headers().toString();

                logger.debug("Request ID: " + requestId + ", Received response: Status code: " + statusCode
                        + ", Headers: " + responseHeaders);

                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully executed " + operation + " for "
                            + entityId + (statusCode == 409 ? " (already registered)" : ""));
                    return response;
                } else {
                    logger.error("Request ID: " + requestId + ", Failed to execute " + operation + " for "
                            + entityId + ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new StatusListServerException(
                            "Failed to execute " + operation + " for " + entityId + ". Status code: "
                                    + statusCode,
                            statusCode);
                }
            } catch (ConnectException | java.net.http.HttpTimeoutException e) {
                if (attempt <= retryCount) {
                    logger.warn("Request ID: " + requestId + ", Attempt: " + attempt
                            + ", Connection/Timeout failed for " + entityId + ", retrying... Error: " + e.getMessage());
                    performSleepWithBackoff(attempt);
                    continue;
                }
                logger.error("Request ID: " + requestId + ", Failed to connect/timeout for " + entityId + " after "
                        + retryCount + " retries: " + e.getMessage(), e);
                throw new StatusListException("Failed to " + operation + ": " + entityId + " after " + retryCount + " retries, Server URL: " + serverUrl, e);
            } catch (IOException | InterruptedException e) {
                if (attempt <= retryCount && e instanceof IOException) {
                    logger.warn("Request ID: " + requestId + ", Attempt: " + attempt
                            + ", Transient error for " + entityId + ", retrying... Error: " + e.getMessage());
                    performSleepWithBackoff(attempt);
                    continue;
                }
                logger.error("Request ID: " + requestId + ", Failed to execute " + operation + " for " + entityId +
                        ": " + e.getMessage(), e);
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                throw new StatusListException("Failed to " + operation + ": " + entityId + ", Server URL: " + serverUrl, e);
            }
        }
        // Should be unreachable, but required for compilation
        throw new StatusListException("Exceeded maximum retries for " + operation + ": " + entityId + ", Server URL: " + serverUrl);
    }

    private void performSleepWithBackoff(int attempt) throws StatusListException {
        try {
            performSleep(1000L * attempt); // Exponential backoff: 1s, 2s, 3s, etc.
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new StatusListException("Interrupted during retry", ie);
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

        String jsonPayload;
        try {
            jsonPayload = objectMapper.writeValueAsString(issuerRecord);
        } catch (JsonProcessingException e) {
            logger.error("Request ID: " + requestId + ", Failed to serialize issuer record: " + issuerId, e);
            throw new StatusListException("Failed to serialize issuer record: " + issuerId, e);
        }

        HttpRequest.Builder requestBuilder = buildBaseRequest(requestId, "credentials")
                .timeout(Duration.ofSeconds(30)) // Add explicit timeout
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

        executeRequestWithRetry(requestBuilder, requestId, issuerId, "register issuer");
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

    protected void performSleep(long millis) throws InterruptedException {
        Thread.sleep(millis);
    }
}