package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;

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
            logger.debug(
                    "Request ID: " + requestId + ", Publishing record for credentialId: " + credentialId);

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
                    throw new StatusListServerException(
                            "Failed to publish record for credentialId: " + credentialId + ". Status code: "
                                    + statusCode,
                            statusCode);
                }
            });

        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Failed to publish record for credentialId: "
                            + credentialId
                            + ": "
                            + e.getMessage(),
                    e);
            throw new StatusListException(
                    "Failed to publish record for credentialId: " + credentialId, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error publishing record for credentialId: "
                    + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error publishing record for credentialId: " + credentialId, e);
        }
    }

    public void updateRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        String requestId = UUID.randomUUID().toString();
        String credentialId = statusRecord.getCredentialId();

        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug(
                    "Request ID: " + requestId + ", Updating record for credentialId: " + credentialId);

            HttpPatch httpPatch = new HttpPatch(serverUrl + "credentials");
            httpPatch.setHeader("Content-Type", "application/json");
            httpPatch.setHeader("X-Request-ID", requestId);
            httpPatch.setEntity(new StringEntity(jsonPayload));

            if (authToken != null && !authToken.isEmpty()) {
                httpPatch.setHeader("Authorization", "Bearer " + authToken);
            }

            httpClient.execute(httpPatch, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                if (statusCode >= 200 && statusCode < 300) {
                    logger.info("Request ID: " + requestId + ", Successfully updated record for credentialId: "
                            + credentialId);
                    return null;
                } else {
                    logger.error(
                            "Request ID: " + requestId + ", Failed to update record for credentialId: " + credentialId +
                                    ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new StatusListServerException(
                            "Failed to update record for credentialId: " + credentialId + ". Status code: "
                                    + statusCode,
                            statusCode);
                }
            });
        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Failed to update record for credentialId: "
                            + credentialId
                            + ": "
                            + e.getMessage(),
                    e);
            throw new StatusListException("Failed to update record for credentialId: " + credentialId, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error updating record for credentialId: "
                    + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error updating record for credentialId: " + credentialId, e);
        }
    }

    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        logger.info(
                "Request ID: "
                        + requestId
                        + ", Registering issuer: "
                        + issuerId
                        + " with server: "
                        + serverUrl);

        // Create a simple record with just the required fields for issuer registration
        TokenStatusRecord issuerRecord = new TokenStatusRecord();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);

        try {
            String jsonPayload = objectMapper.writeValueAsString(issuerRecord);
            logger.debug(
                    "Request ID: "
                            + requestId
                            + ", Registering issuer: "
                            + issuerId
                            + ", Payload: "
                            + jsonPayload);

            HttpPost httpPost = new HttpPost(serverUrl + "credentials");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                String responseHeaders = Arrays.toString(response.getHeaders());

                logger.debug(
                        "Request ID: "
                                + requestId
                                + ", Received response: Status code: "
                                + statusCode
                                + ", Headers: "
                                + responseHeaders
                                + ", Body: "
                                + responseBody);

                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully registered issuer: " + issuerId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    return Boolean.TRUE; // Success
                } else {
                    throw new StatusListServerException(
                            "Failed to register issuer: " + issuerId +
                                    ", Status code: " + statusCode +
                                    ", Response: " + responseBody,
                            statusCode);
                }
            });
        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Failed to register issuer: "
                            + issuerId
                            + ": "
                            + e.getMessage()
                            + ", Server URL: "
                            + serverUrl,
                    e);
            throw new StatusListException(
                    "Failed to register issuer: " + issuerId + ", Server URL: " + serverUrl, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error registering issuer: " + issuerId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error registering issuer: " + issuerId, e);
        }
    }

    private void validateStatusRecord(TokenStatusRecord statusRecord) throws StatusListException {
        String credentialId = statusRecord.getCredentialId() != null ? statusRecord.getCredentialId() : "unknown";

        // Check required fields according to the specification
        if (statusRecord.getCredentialId() == null || statusRecord.getCredentialId().isEmpty()) {
            throw new StatusListException(
                    "Credential ID (sub) is required for credentialId: " + credentialId);
        }

        // Ensure both iss and issuer fields are set
        if (statusRecord.getIssuerId() == null || statusRecord.getIssuerId().isEmpty()) {
            throw new StatusListException(
                    "Issuer ID (iss) is required for credentialId: " + credentialId);
        }

        // Make sure issuer field is set if not already
        if (statusRecord.getIssuer() == null || statusRecord.getIssuer().isEmpty()) {
            statusRecord.setIssuer(statusRecord.getIssuerId());
        }

        // Require public_key to be set by the caller
        if (statusRecord.getPublicKey() == null) {
            throw new StatusListException(
                    "Public key is required and must be retrieved from Keycloak's KeyManager for credentialId: "
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

    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        logger.debug("Request ID: " + requestId + ", Checking if status list exists: " + statusListId);

        HttpGet httpGet = new HttpGet(serverUrl + "statuslists/" + statusListId);
        httpGet.setHeader("X-Request-ID", requestId);

        try {
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                if (statusCode == 200) {
                    logger.info("Request ID: " + requestId + ", Status list " + statusListId + " exists.");
                    return true;
                } else if (statusCode == 404) {
                    logger.info("Request ID: " + requestId + ", Status list " + statusListId + " does not exist.");
                    return false;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to check status list " + statusListId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new StatusListServerException(
                            "Failed to check status list " + statusListId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Error checking status list "
                            + statusListId
                            + ": "
                            + e.getMessage(),
                    e);
            throw new StatusListException("Error checking status list " + statusListId, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error checking status list " + statusListId + ": "
                    + e.getMessage(), e);
            throw new StatusListException("Unexpected error checking status list " + statusListId, e);
        }
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
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Failed to publish or update status list "
                            + listId
                            + ": "
                            + e.getMessage(),
                    e);
            throw e;
        }
    }

    private void publishStatusList(StatusListPayload payload, String requestId)
            throws StatusListException {
        String listId = payload.listId();
        logger.debug("Request ID: " + requestId + ", Publishing new status list: " + listId);

        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPost httpPost = new HttpPost(serverUrl + "statuslists");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            if (authToken != null && !authToken.isEmpty()) {
                httpPost.setHeader("Authorization", "Bearer " + authToken);
            }

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300) {
                    logger.info("Request ID: " + requestId + ", Successfully published status list: " + listId);
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to publish status list " + listId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new StatusListServerException(
                            "Failed to publish status list " + listId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Error publishing status list "
                            + listId
                            + ": "
                            + e.getMessage(),
                    e);
            throw new StatusListException("Error publishing status list " + listId, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error publishing status list " + listId + ": "
                    + e.getMessage(), e);
            throw new StatusListException("Unexpected error publishing status list " + listId, e);
        }
    }

    private void updateStatusList(StatusListPayload payload, String requestId)
            throws StatusListException {
        String listId = payload.listId();
        logger.debug("Request ID: " + requestId + ", Updating existing status list: " + listId);

        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPatch httpPatch = new HttpPatch(serverUrl + "statuslists/" + listId);
            httpPatch.setHeader("Content-Type", "application/json");
            httpPatch.setHeader("X-Request-ID", requestId);
            httpPatch.setEntity(new StringEntity(jsonPayload));

            if (authToken != null && !authToken.isEmpty()) {
                httpPatch.setHeader("Authorization", "Bearer " + authToken);
            }

            httpClient.execute(httpPatch, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300) {
                    logger.info("Request ID: " + requestId + ", Successfully updated status list: " + listId);
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to update status list " + listId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    throw new StatusListServerException(
                            "Failed to update status list " + listId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (StatusListServerException e) {
            throw e;
        } catch (IOException e) {
            logger.error(
                    "Request ID: "
                            + requestId
                            + ", Error updating status list "
                            + listId
                            + ": "
                            + e.getMessage(),
                    e);
            throw new StatusListException("Error updating status list " + listId, e);
        } catch (Exception e) {
            logger.error("Request ID: " + requestId + ", Unexpected error updating status list " + listId + ": "
                    + e.getMessage(), e);
            throw new StatusListException("Unexpected error updating status list " + listId, e);
        }
    }

    /**
     * Checks the health status of the status list server.
     *
     * @return true if the server is healthy, false otherwise
     */
    public boolean checkServerHealth() {
        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking server health at: %s", requestId, serverUrl);

        HttpGet httpGet = new HttpGet(this.serverUrl + "health");
        httpGet.setHeader("X-Request-ID", requestId);

        try {
            return httpClient.execute(
                    httpGet,
                    response -> {
                        int statusCode = response.getCode();
                        if (statusCode >= 200 && statusCode < 300) {
                            logger.infof("Request ID: %s, Server health check successful.", requestId);
                            return true;
                        }

                        logger.warnf(
                                "Request ID: %s, Server health check failed. Status code: %d",
                                requestId, statusCode);
                        return false;
                    });
        } catch (IOException e) {
            logger.errorf(e, "Request ID: %s, Error during server health check", requestId);
            return false;
        }
    }

    public record StatusListPayload(
            @JsonProperty("list_id") String listId,
            List<StatusEntry> status) {
        public record StatusEntry(int index, String status) {
        }
    }
}
