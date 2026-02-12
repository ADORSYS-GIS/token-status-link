package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.IssuerRegistrationPayload;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.adorsys.keycloakstatuslist.service.http.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.utils.StringUtil;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);

    private final String serverUrl;
    private final String authToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public StatusListService(String serverUrl, String authToken, HttpClient httpClient) {
        // Ensure serverUrl ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        logger.infof("Initialized StatusListService with serverUrl: %s", this.serverUrl);
    }

    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        logger.infof(
                "Request ID: %s, Registering issuer: %s with server: %s", requestId, issuerId, serverUrl);

        // Create a simple record with just the required fields for issuer registration
        IssuerRegistrationPayload issuerRecord = new IssuerRegistrationPayload();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);

        try {
            String jsonPayload = objectMapper.writeValueAsString(issuerRecord);
            logger.debugf(
                    "Request ID: %s, Registering issuer: %s, Payload: %s",
                    requestId,
                    issuerId,
                    jsonPayload);

            HttpPost httpPost = new HttpPost(serverUrl + "credentials");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                String responseHeaders = Arrays.toString(response.getHeaders());

                logger.debugf(
                        "Request ID: %s, Received response: Status code: %d, Headers: %s, Body: %s",
                        requestId,
                        statusCode,
                        responseHeaders,
                        responseBody);

                if (statusCode >= HttpStatus.SC_OK && statusCode < 300 || statusCode == HttpStatus.SC_CONFLICT) {
                    logger.infof(
                            "Request ID: %s, Successfully registered issuer: %s%s",
                            requestId,
                            issuerId,
                            statusCode == HttpStatus.SC_CONFLICT ? " (already registered)" : "");
                    return Boolean.TRUE; // Success
                } else {
                    throw new StatusListServerException(
                            "Failed to register issuer: " + issuerId +
                                    ", Status code: " + statusCode +
                                    ", Response: " + responseBody,
                            statusCode);
                }
            });
        } catch (IOException e) {
            logger.errorf(
                    "Request ID: %s, Failed to register issuer: %s: %s, Server URL: %s",
                    requestId,
                    issuerId,
                    e.getMessage(),
                    serverUrl,
                    e);
            throw new StatusListException(
                    "Failed to register issuer: " + issuerId + ", Server URL: " + serverUrl, e);
        }
    }

    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking if status list exists: %s", requestId, statusListId);

        HttpGet httpGet = new HttpGet(serverUrl + "statuslists/" + statusListId);
        httpGet.setHeader("X-Request-ID", requestId);

        try {
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                if (statusCode == HttpStatus.SC_OK) {
                    logger.infof("Request ID: %s, Status list %s exists.", requestId, statusListId);
                    return true;
                } else if (statusCode == HttpStatus.SC_NOT_FOUND) {
                    logger.infof("Request ID: %s, Status list %s does not exist.", requestId, statusListId);
                    return false;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.errorf(
                            "Request ID: %s, Failed to check status list %s. Status code: %d, Response: %s",
                            requestId,
                            statusListId,
                            statusCode,
                            responseBody);
                    throw new StatusListServerException(
                            "Failed to check status list " + statusListId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (IOException e) {
            logger.errorf(
                    "Request ID: %s, Error checking status list %s: %s",
                    requestId,
                    statusListId,
                    e.getMessage(),
                    e);
            throw new StatusListException("Error checking status list " + statusListId, e);
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
            logger.errorf(
                    "Request ID: %s, Failed to publish or update status list %s: %s",
                    requestId,
                    listId,
                    e.getMessage(),
                    e);
            throw e;
        }
    }

    private void publishStatusList(StatusListPayload payload, String requestId)
            throws StatusListException {
        String listId = payload.listId();
        logger.debugf("Request ID: %s, Publishing new status list: %s", requestId, listId);

        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPost httpPost = new HttpPost(serverUrl + "statuslists/publish");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));

            if (StringUtil.isBlank(authToken)) {
                throw new IllegalStateException("Auth token required but blank");
            }

            httpPost.setHeader("Authorization", "Bearer " + authToken);

            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                if (statusCode >= HttpStatus.SC_OK && statusCode < 300) {
                    logger.infof("Request ID: %s, Successfully published status list: %s", requestId, listId);
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.errorf(
                            "Request ID: %s, Failed to publish status list %s. Status code: %d, Response: %s",
                            requestId,
                            listId,
                            statusCode,
                            responseBody);
                    throw new StatusListServerException(
                            "Failed to publish status list " + listId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (IOException e) {
            logger.errorf(
                    "Request ID: %s, Error publishing status list %s: %s",
                    requestId,
                    listId,
                    e.getMessage(),
                    e);
            throw new StatusListException("Error publishing status list " + listId, e);
        }
    }

    public void updateStatusList(StatusListPayload payload, String requestId)
            throws StatusListException {
        String listId = payload.listId();
        logger.debugf("Request ID: %s, Updating existing status list: %s", requestId, listId);

        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPatch httpPatch = new HttpPatch(serverUrl + "statuslists/update");
            httpPatch.setHeader("Content-Type", "application/json");
            httpPatch.setHeader("X-Request-ID", requestId);
            httpPatch.setEntity(new StringEntity(jsonPayload));

            if (StringUtil.isBlank(authToken)) {
                throw new IllegalStateException("Auth token required but blank");
            }

            httpPatch.setHeader("Authorization", "Bearer " + authToken);

            httpClient.execute(httpPatch, response -> {
                int statusCode = response.getCode();
                if (statusCode >= HttpStatus.SC_OK && statusCode < 300) {
                    logger.infof("Request ID: %s, Successfully updated status list: %s", requestId, listId);
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.errorf(
                            "Request ID: %s, Failed to update status list %s. Status code: %d, Response: %s",
                            requestId,
                            listId,
                            statusCode,
                            responseBody);
                    throw new StatusListServerException(
                            "Failed to update status list " + listId + ". Status code: " + statusCode,
                            statusCode);
                }
            });
        } catch (IOException e) {
            logger.errorf(
                    "Request ID: %s, Error updating status list %s: %s",
                    requestId,
                    listId,
                    e.getMessage(),
                    e);
            throw new StatusListException("Error updating status list " + listId, e);
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
                        if (statusCode >= HttpStatus.SC_OK && statusCode < 300) {
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
        public record StatusEntry(long index, String status) {
        }
    }
}
