package com.adorsys.keycloakstatuslist.service;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServiceDisabledException;
import com.adorsys.keycloakstatuslist.exception.StatusListCommunicationException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * Service class for interacting with the Status List server according to the SD-JWT Status List specification.
 */
public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    private final StatusListConfig config;

    public StatusListService(StatusListConfig config) {
        this.config = config;
    }

    /**
     * Registers a new credential with the Status List server.
     *
     * @param statusRecord the credential status record to register
     * @throws StatusListException if registration fails
     */
    public void registerCredential(TokenStatusRecord statusRecord) throws StatusListException {
        if (!config.isEnabled()) {
            logger.debug("Status list service is disabled.");
            throw new StatusListServiceDisabledException("Status list service is disabled");
        }

        // Ensure all required fields are set
        validateStatusRecord(statusRecord);

        logger.debug("Registering credential: " + statusRecord.getCredentialId());
        // Normalize URL to ensure it ends with /
        String baseUrl = config.getServerUrl().endsWith("/") ?
                config.getServerUrl() : config.getServerUrl() + "/";
        String endpoint = baseUrl + "credentials";

        executeRequest(new HttpPost(endpoint), statusRecord);
    }

    /**
     * Revokes a credential in the Status List server.
     *
     * @param statusRecord the credential status record to revoke
     * @throws StatusListException if revocation fails
     */
    public void revokeCredential(TokenStatusRecord statusRecord) throws StatusListException {
        if (!config.isEnabled()) {
            throw new StatusListServiceDisabledException("Status list service is disabled");
        }

        // Make sure status is set to REVOKED
        statusRecord.setStatus(TokenStatus.REVOKED);
        if (statusRecord.getRevokedAt() == null) {
            statusRecord.setRevokedAt(java.time.Instant.now());
        }

        validateStatusRecord(statusRecord);

        // Update the credential instead of using a specific revoke endpoint
        logger.debug("Revoking credential: " + statusRecord.getCredentialId());
        String baseUrl = config.getServerUrl().endsWith("/") ?
                config.getServerUrl() : config.getServerUrl() + "/";
        String endpoint = baseUrl + "credentials";

        executeRequest(new HttpPost(endpoint), statusRecord);
    }

    /**
     * Validates that required fields are set in the status record.
     *
     * @param statusRecord the record to validate
     * @throws StatusListException if validation fails
     */
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

        if (statusRecord.getStatus() == TokenStatus.ACTIVE) {
            if (statusRecord.getIssuedAt() == null) {
                statusRecord.setIssuedAt(java.time.Instant.now());
            }
            if (statusRecord.getExpiresAt() == null) {
                // Default to 1 hour if not specified
                statusRecord.setExpiresAt(java.time.Instant.now().plusSeconds(3600));
            }
        } else if (statusRecord.getStatus() == TokenStatus.REVOKED) {
            if (statusRecord.getRevokedAt() == null) {
                statusRecord.setRevokedAt(java.time.Instant.now());
            }
        }
    }

    /**
     * Checks the status of a credential with the Status List server.
     *
     * @param credentialId the ID of the credential to check
     * @return the current status of the credential
     * @throws StatusListException if status check fails
     */
    public TokenStatus checkCredentialStatus(String credentialId) throws StatusListException {
        if (!config.isEnabled()) {
            throw new StatusListServiceDisabledException("Status list service is disabled");
        }

        logger.debug("Checking status of credential: " + credentialId);
        String baseUrl = config.getServerUrl().endsWith("/") ?
                config.getServerUrl() : config.getServerUrl() + "/";
        String endpoint = baseUrl + "credentials/" + credentialId;

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.of(config.getConnectTimeout(), TimeUnit.MILLISECONDS))
                .setResponseTimeout(Timeout.of(config.getReadTimeout(), TimeUnit.MILLISECONDS))
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            HttpGet request = new HttpGet(endpoint);

            String authToken = config.getAuthToken();
            if (authToken != null && !authToken.isEmpty()) {
                request.setHeader("Authorization", "Bearer " + authToken);
            }

            try (CloseableHttpResponse response = executeWithRetry(httpClient, request)) {
                int statusCode = response.getCode();

                if (statusCode == 200) {
                    // Parse response to get the status
                    String responseJson = new String(response.getEntity().getContent().readAllBytes());
                    TokenStatusRecord record = objectMapper.readValue(responseJson, TokenStatusRecord.class);
                    return record.getStatus();
                } else if (statusCode == 404) {
                    // Credential not found
                    logger.warn("Credential not found: " + credentialId);
                    return null;
                } else {
                    throw new StatusListServerException("Failed to check credential status. Status code: " + statusCode, statusCode);
                }
            }
        } catch (IOException e) {
            throw new StatusListCommunicationException("Failed to communicate with status list server", e);
        }
    }

    /**
     * Common method to execute HTTP requests with retry logic.
     */
    private void executeRequest(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request, TokenStatusRecord statusRecord)
            throws StatusListException {

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.of(config.getConnectTimeout(), TimeUnit.MILLISECONDS))
                .setResponseTimeout(Timeout.of(config.getReadTimeout(), TimeUnit.MILLISECONDS))
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            request.setHeader("Content-Type", "application/json");

            String authToken = config.getAuthToken();
            if (authToken != null && !authToken.isEmpty()) {
                request.setHeader("Authorization", "Bearer " + authToken);
            }

            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Sending payload: " + jsonPayload);
            request.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON));

            try (CloseableHttpResponse response = executeWithRetry(httpClient, request)) {
                int statusCode = response.getCode();

                if (statusCode < 200 || statusCode >= 300) {
                    try {
                        String responseBody = new String(response.getEntity().getContent().readAllBytes());
                        logger.error("Request failed. Status code: " + statusCode + ", Response: " + responseBody);
                    } catch (Exception e) {
                        logger.error("Request failed. Status code: " + statusCode);
                    }
                    throw new StatusListServerException(
                            "Request failed. Status code: " + statusCode,
                            statusCode);
                }
            }

        } catch (IOException e) {
            throw new StatusListCommunicationException("Failed to communicate with status list server", e);
        }
    }

    private CloseableHttpResponse executeWithRetry(CloseableHttpClient httpClient,
                                                   org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request)
            throws IOException, StatusListServerException {

        int retryCount = config.getRetryCount();
        int attempt = 0;

        while (attempt <= retryCount) {
            try {
                attempt++;
                logger.debug("Attempt " + attempt + " for " + request.getMethod() + " request to " + request.getUri());

                CloseableHttpResponse response = httpClient.execute(request);
                int statusCode = response.getCode();

                if (statusCode >= 200 && statusCode < 300) {
                    return response;
                } else {
                    logger.warn("Request failed. Status code: " + statusCode);

                    // Attempt to log response body for better diagnostics
                    try {
                        String responseBody = new String(response.getEntity().getContent().readAllBytes());
                        logger.warn("Response body: " + responseBody);
                    } catch (Exception e) {
                        logger.warn("Could not read response body", e);
                    }

                    response.close();

                    if (attempt > retryCount || !isRetryable(statusCode)) {
                        throw new StatusListServerException(
                                "Request failed after " + attempt + " attempts. Status code: " + statusCode,
                                statusCode);
                    }
                }

                long backoffTime = (long) Math.pow(2, attempt) * 100;
                Thread.sleep(backoffTime);

            } catch (InterruptedException | URISyntaxException e) {
                Thread.currentThread().interrupt();
                logger.error("Thread interrupted during retry wait", e);
                throw new IOException("Thread interrupted during retry wait", e);
            }
        }

        throw new IOException("Failed after " + retryCount + " attempts");
    }

    private boolean isRetryable(int statusCode) {
        return statusCode == 429 || statusCode >= 500;
    }
}