package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private final String serverUrl;
    private final String authToken;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public StatusListService(String serverUrl, String authToken, StatusListConfig realmConfig) {
        this(serverUrl, authToken, createDefaultHttpClient(realmConfig));
    }

    public StatusListService(String serverUrl, String authToken, CloseableHttpClient httpClient) {
        // Ensure serverUrl ends with a slash
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        logger.info(
                "Initialized StatusListService with serverUrl: " + this.serverUrl);
    }

    private static CloseableHttpClient createDefaultHttpClient(StatusListConfig realmConfig) {
        RequestConfig requestConfig = getRequestConfig(realmConfig);
        HttpRequestRetryStrategy retryStrategy = getHttpRequestRetryStrategy(realmConfig);

        return HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryStrategy(retryStrategy)
                .build();
    }

    private static RequestConfig getRequestConfig(StatusListConfig realmConfig) {
        Timeout connectTimeout = Timeout.ofMilliseconds(realmConfig.getConnectTimeout());
        Timeout responseTimeout = Timeout.ofMilliseconds(realmConfig.getReadTimeout());

        return RequestConfig.custom()
                .setConnectionRequestTimeout(connectTimeout)
                .setResponseTimeout(responseTimeout)
                .build();
    }

    private static HttpRequestRetryStrategy getHttpRequestRetryStrategy(StatusListConfig realmConfig) {
        int maxRetries = realmConfig.getRetryCount();

        return new HttpRequestRetryStrategy() {
            @Override
            public boolean retryRequest(HttpRequest httpRequest, IOException e, int execCount, HttpContext httpContext) {
                logger.warnf("[Attempt %d/%d] Error sending status: %s", execCount, maxRetries, e.getMessage());
                return execCount <= maxRetries;
            }

            @Override
            public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
                logger.warnf("[Attempt %d/%d] Failed to send status: %d %s",
                        execCount, maxRetries, response.getCode(), response.getReasonPhrase());
                int status = response.getCode();
                return execCount <= maxRetries && (status >= 500);
            }

            @Override
            public TimeValue getRetryInterval(HttpResponse httpResponse, int execCount, HttpContext httpContext) {
                // Exponential backoff: 1s, 2s, 4s
                return TimeValue.ofSeconds((long) Math.pow(2, execCount - 1));
            }
        };
    }


    public void publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        validateStatusRecord(statusRecord);
        String requestId = UUID.randomUUID().toString(); // Correlation ID for tracing
        String credentialId = statusRecord.getCredentialId(); // For logging context

        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Request ID: " + requestId + ", Publishing record for credentialId: " + credentialId);

            HttpPost request = new HttpPost(serverUrl + "credentials");
            request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
            request.setHeader("X-Request-ID", requestId);
            if (authToken != null && !authToken.isEmpty()) {
                request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
            }
            request.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

            logger.debug("Request ID: " + requestId + ", Sending HTTP request to: " + request.getUri());

            httpClient.execute(request, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully published record for credentialId: "
                            + credentialId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    return null;
                } else {
                    logger.error("Request ID: " + requestId + ", Failed to publish record for credentialId: "
                            + credentialId +
                            ". Status code: " + statusCode);
                    throw new IOException(new StatusListServerException(
                            "Failed to publish record for credentialId: " + credentialId + ". Status code: "
                                    + statusCode,
                            statusCode));
                }
            });
        } catch (IOException | URISyntaxException e) {
            if (e.getCause() instanceof StatusListServerException) {
                throw (StatusListServerException) e.getCause();
            }
            logger.error(
                    "Request ID: " + requestId + ", Failed to publish record for credentialId: " +
                            credentialId + ": " + e.getMessage(),
                    e);
            throw new StatusListException("Failed to publish record for credentialId: " + credentialId, e);
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
            logger.debug(
                    "Request ID: " + requestId + ", Registering issuer: " + issuerId +
                            ", Payload: " + jsonPayload);

            HttpPost request = new HttpPost(serverUrl + "credentials");
            request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
            request.setHeader("X-Request-ID", requestId);

            request.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

            logger.debug("Request ID: " + requestId + ", Sending HTTP request to: " + request.getUri() +
                    ", Headers: " + request.getHeaders());

            httpClient.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully registered issuer: " + issuerId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    return null;
                } else {
                    throw new IOException(new StatusListServerException(
                            "Failed to register issuer: " + issuerId +
                                    ", Status code: " + statusCode,
                            statusCode));
                }
            });
        } catch (IOException | URISyntaxException e) {
            if (e.getCause() instanceof StatusListServerException) {
                throw (StatusListServerException) e.getCause();
            }
            logger.error("Request ID: " + requestId + ", Failed to register issuer: " + issuerId +
                    ": " + e.getMessage() + ", Server URL: " + serverUrl, e);
            throw new StatusListException("Failed to register issuer: " + issuerId +
                    ", Server URL: " + serverUrl, e);
        }
    }

    public boolean checkStatusListExists(String statusListId) throws IOException {
        HttpGet httpGet = new HttpGet(serverUrl + "statuslists/" + statusListId);
        return httpClient.execute(httpGet, response -> {
            if (response.getCode() == 404) {
                logger.infof("Status list %s does not exist on server.", statusListId);
                return false;
            } else if (response.getCode() == 200) {
                logger.infof("Status list %s exists on server.", statusListId);
                return true;
            } else {
                String reason = response.getReasonPhrase();
                logger.errorf("Failed to verify existence of status list %s: %d %s", statusListId,
                        response.getCode(), reason);
                throw new IOException("Failed to verify status list existence: " + response.getCode());
            }
        });
    }

    public void publishNewList(Object payload) throws IOException {
        performListOperation("publish", payload);
    }

    public void updateList(Object payload) throws IOException {
        performListOperation("update", payload);
    }

    private void performListOperation(String operation, Object payload) throws IOException {
        String path = "update".equals(operation) ? "statuslists/update" : "statuslists/publish";
        HttpUriRequestBase request = "update".equals(operation) ? new HttpPatch(serverUrl + path) : new HttpPost(serverUrl + path);

        request.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
        if (authToken != null && !authToken.isEmpty()) {
            request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
        }

        String jsonPayload = objectMapper.writeValueAsString(payload);
        logger.debugf("Sending payload for %s: %s", operation, jsonPayload);
        request.setEntity(new StringEntity(jsonPayload, StandardCharsets.UTF_8, false));

        httpClient.execute(request, response -> {
            if (response.getCode() < 200 || response.getCode() >= 300) {
                logger.errorf("Failed to %s status list: %d %s",
                        operation, response.getCode(), response.getReasonPhrase());
                throw new IOException("Non-success response: " + response.getCode());
            } else {
                logger.infof("Successfully %s status list on server.", operation);
                return null;
            }
        });
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