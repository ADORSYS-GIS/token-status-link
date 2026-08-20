package com.adorsys.keycloakstatuslist.client;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.IssuerRegistrationPayload;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JsonSerialization;

/**
 * Apache HTTP Client implementation of StatusListHttpClient with circuit breaker support.
 */
public class ApacheHttpStatusListClient implements StatusListHttpClient {

    private static final Logger logger = Logger.getLogger(ApacheHttpStatusListClient.class);

    private static final String API_V1_PATH = "api/v1";
    private static final String CREDENTIALS_PATH = API_V1_PATH + "/credentials";
    private static final String STATUS_LISTS_PATH = API_V1_PATH + "/status-lists";
    private static final String STATUS_LIST_STATUSES_PATH = "statuses";
    private static final String HEALTH_PATH = "health";
    private static final String STATUS_LIST_JWT_MEDIA_TYPE = "application/statuslist+jwt";

    private final String serverUrl;
    private final String authToken;
    private final CloseableHttpClient httpClient;
    private final CircuitBreaker circuitBreaker;

    /**
     * Creates a new Apache HTTP client for status list operations.
     *
     * @param serverUrl the status list server URL
     * @param authToken the authentication token
     * @param httpClient the HTTP client to use
     * @param circuitBreaker optional circuit breaker (can be null to disable)
     */
    public ApacheHttpStatusListClient(
            String serverUrl, String authToken, CloseableHttpClient httpClient, CircuitBreaker circuitBreaker) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.circuitBreaker = circuitBreaker;

        logger.infof(
                "Initialized ApacheHttpStatusListClient with serverUrl: %s, circuitBreaker: %s",
                this.serverUrl, circuitBreaker != null ? "enabled" : "disabled");
    }

    @Override
    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        checkCircuitBreaker();

        String requestId = UUID.randomUUID().toString();
        logger.infof("Request ID: %s, Registering issuer: %s with server: %s", requestId, issuerId, serverUrl);

        IssuerRegistrationPayload issuerRecord = new IssuerRegistrationPayload();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);

        executeStatusListRequest(
                requestId,
                () -> {
                    String jsonPayload = JsonSerialization.mapper.writeValueAsString(issuerRecord);
                    logger.debugf(
                            "Request ID: %s, Registering issuer: %s, Payload: %s", requestId, issuerId, jsonPayload);

                    HttpPost httpPost = new HttpPost(credentialsUrl());
                    configureJsonRequest(httpPost, requestId, jsonPayload);

                    httpClient.execute(httpPost, response -> {
                        String responseHeaders = response.getHeaders().toString();
                        logger.debugf(
                                "Request ID: %s, Received response: Status code: %d, Headers: %s, Body: %s",
                                requestId,
                                response.getCode(),
                                responseHeaders,
                                (response.getEntity() != null ? "present" : "empty"));

                        handleResponse(
                                response,
                                requestId,
                                "Successfully registered issuer: " + issuerId,
                                "Failed to register issuer: " + issuerId,
                                true);
                        return Boolean.TRUE;
                    });
                    return null;
                },
                "Timeout registering issuer: " + issuerId + ", Server URL: " + serverUrl,
                "Failed to register issuer: " + issuerId + ", Server URL: " + serverUrl);
    }

    @Override
    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        checkCircuitBreaker();

        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking if status list exists: %s", requestId, statusListId);

        HttpGet httpGet = new HttpGet(statusListUrl(statusListId));
        configureCommonHeaders(httpGet, requestId);
        httpGet.setHeader("Accept", STATUS_LIST_JWT_MEDIA_TYPE);

        return executeStatusListRequest(
                requestId,
                () -> httpClient.execute(
                        httpGet, response -> handleStatusListExistsResponse(response, requestId, statusListId)),
                "Timeout checking status list " + statusListId,
                "Error checking status list " + statusListId);
    }

    @Override
    public void publishStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();

        String listId = payload.listId();
        logger.debugf("Request ID: %s, Publishing new status list: %s", requestId, listId);

        executeStatusListRequest(
                requestId,
                () -> {
                    String jsonPayload = statusEntriesJson(payload);
                    HttpPut httpPut = new HttpPut(statusListStatusesUrl(listId));
                    configureJsonRequest(httpPut, requestId, jsonPayload);

                    return httpClient.execute(
                            httpPut,
                            response -> handleResponse(
                                    response,
                                    requestId,
                                    "Successfully published status list: " + listId,
                                    "Failed to publish status list " + listId,
                                    false));
                },
                "Timeout publishing status list " + listId,
                "Error publishing status list " + listId);
    }

    @Override
    public void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();

        String listId = payload.listId();
        logger.debugf("Request ID: %s, Updating existing status list: %s", requestId, listId);

        executeStatusListRequest(
                requestId,
                () -> {
                    String jsonPayload = statusEntriesJson(payload);
                    HttpPatch httpPatch = new HttpPatch(statusListStatusesUrl(listId));
                    configureJsonRequest(httpPatch, requestId, jsonPayload);

                    return httpClient.execute(
                            httpPatch,
                            response -> handleResponse(
                                    response,
                                    requestId,
                                    "Successfully updated status list: " + listId,
                                    "Failed to update status list " + listId,
                                    false));
                },
                "Timeout updating status list " + listId,
                "Error updating status list " + listId);
    }

    @Override
    public boolean checkServerHealth() {
        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking server health at: %s", requestId, serverUrl);

        HttpGet httpGet = new HttpGet(this.serverUrl + HEALTH_PATH);
        configureCommonHeaders(httpGet, requestId);

        try {
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                if (statusCode >= HttpStatus.SC_OK && statusCode < 300) {
                    logger.infof("Request ID: %s, Server health check successful.", requestId);
                    return true;
                }

                logger.warnf("Request ID: %s, Server health check failed. Status code: %d", requestId, statusCode);
                return false;
            });
        } catch (IOException e) {
            logger.errorf(e, "Request ID: %s, Error during server health check", requestId);
            return false;
        }
    }

    @Override
    public String getServerUrl() {
        return serverUrl;
    }

    private String credentialsUrl() {
        return serverUrl + CREDENTIALS_PATH;
    }

    private String statusListUrl(String statusListId) {
        return serverUrl + STATUS_LISTS_PATH + "/" + statusListId;
    }

    private String statusListStatusesUrl(String statusListId) {
        return statusListUrl(statusListId) + "/" + STATUS_LIST_STATUSES_PATH;
    }

    private String statusEntriesJson(StatusListPayload payload) throws IOException {
        List<StatusEntryPayload> statusEntries = new ArrayList<>();
        for (StatusListPayload.StatusEntry statusEntry : payload.status()) {
            statusEntries.add(new StatusEntryPayload(
                    statusEntry.index(), statusEntry.status().getCode()));
        }

        return JsonSerialization.mapper.writeValueAsString(new StatusesPayload(statusEntries));
    }

    private record StatusesPayload(List<StatusEntryPayload> statuses) {}

    private record StatusEntryPayload(long index, int status) {}

    /**
     * Handles HTTP response with success/error logic, logging, and circuit breaker recording.
     *
     * @param response the HTTP response
     * @param requestId the request ID for logging
     * @param successMessage the message to log on success
     * @param errorMessagePrefix the prefix for error messages
     * @param acceptConflict whether to accept HTTP 409 (CONFLICT) as success
     * @return null (for use in response handlers that require a return value)
     * @throws StatusListServerException on error
     */
    private Void handleResponse(
            ClassicHttpResponse response,
            String requestId,
            String successMessage,
            String errorMessagePrefix,
            boolean acceptConflict) {
        int statusCode = response.getCode();
        String responseBody = responseBody(response);

        boolean isSuccess = (statusCode >= HttpStatus.SC_OK && statusCode < 300)
                || (acceptConflict && statusCode == HttpStatus.SC_CONFLICT);

        if (isSuccess) {
            String fullMessage = successMessage;
            if (acceptConflict && statusCode == HttpStatus.SC_CONFLICT) {
                fullMessage += " (already registered)";
            }
            logger.infof("Request ID: %s, %s", requestId, fullMessage);
            recordSuccess();
        } else if (statusCode == HttpStatus.SC_CONFLICT) {
            logger.infof(
                    "Request ID: %s, %s. Status code: %d, Response: %s",
                    requestId, errorMessagePrefix, statusCode, responseBody);
            recordSuccess();
            throw new StatusListServerException(errorMessagePrefix + ". Status code: " + statusCode, statusCode);
        } else {
            logger.errorf(
                    "Request ID: %s, %s. Status code: %d, Response: %s",
                    requestId, errorMessagePrefix, statusCode, responseBody);
            recordFailure();
            throw new StatusListServerException(errorMessagePrefix + ". Status code: " + statusCode, statusCode);
        }
        return null;
    }

    /**
     * Handles HTTP response for status list existence check (special logic: 200=true, 404=false, else error).
     *
     * @param response the HTTP response
     * @param requestId the request ID for logging
     * @param statusListId the status list ID for logging
     * @return true if status list exists (200), false if not found (404)
     * @throws StatusListServerException on other errors
     */
    private boolean handleStatusListExistsResponse(
            ClassicHttpResponse response, String requestId, String statusListId) {
        int statusCode = response.getCode();

        if (statusCode == HttpStatus.SC_OK) {
            logger.infof("Request ID: %s, Status list %s exists.", requestId, statusListId);
            recordSuccess();
            return true;
        } else if (statusCode == HttpStatus.SC_NOT_FOUND) {
            logger.infof("Request ID: %s, Status list %s does not exist.", requestId, statusListId);
            recordSuccess();
            return false;
        } else {
            String responseBody = responseBody(response);
            logger.errorf(
                    "Request ID: %s, Failed to check status list %s. Status code: %d, Response: %s",
                    requestId, statusListId, statusCode, responseBody);
            recordFailure();
            throw new StatusListServerException(
                    "Failed to check status list " + statusListId + ". Status code: " + statusCode, statusCode);
        }
    }

    private <T> T executeStatusListRequest(
            String requestId, StatusListRequest<T> request, String timeoutMessage, String ioErrorMessage)
            throws StatusListException {
        try {
            return request.execute();
        } catch (StatusListServerException e) {
            throw e;
        } catch (InterruptedIOException e) {
            Thread.currentThread().interrupt();
            recordTimeout();
            logger.errorf(e, "Request ID: %s, %s: %s", requestId, timeoutMessage, e.getMessage());
            throw new StatusListException(timeoutMessage, e);
        } catch (IOException e) {
            recordFailure();
            logger.errorf(e, "Request ID: %s, %s: %s", requestId, ioErrorMessage, e.getMessage());
            throw new StatusListException(ioErrorMessage, e);
        }
    }

    private String responseBody(ClassicHttpResponse response) {
        try {
            return response.getEntity() != null ? EntityUtils.toString(response.getEntity()) : "";
        } catch (IOException | ParseException e) {
            return "Unable to read response body: " + e.getMessage();
        }
    }

    @FunctionalInterface
    private interface StatusListRequest<T> {
        T execute() throws IOException;
    }

    /**
     * Configures common headers (X-Request-ID and Authorization) for any HTTP request.
     *
     * @param request the HTTP request to configure
     * @param requestId the request ID to set in the X-Request-ID header
     */
    private void configureCommonHeaders(HttpRequest request, String requestId) {
        request.setHeader("X-Request-ID", requestId);
        if (authToken != null && !authToken.isEmpty()) {
            request.setHeader("Authorization", "Bearer " + authToken);
        }
    }

    /**
     * Configures a JSON request with payload and common headers.
     *
     * @param request the HTTP request to configure
     * @param requestId the request ID to set in the X-Request-ID header
     * @param jsonPayload the JSON payload to set as the request entity
     */
    private void configureJsonRequest(HttpUriRequestBase request, String requestId, String jsonPayload) {
        request.setHeader("Content-Type", "application/json");
        configureCommonHeaders(request, requestId);
        request.setEntity(new StringEntity(jsonPayload));
    }

    /**
     * Checks the circuit breaker state before allowing a request.
     */
    private void checkCircuitBreaker() throws StatusListException {
        if (circuitBreaker != null) {
            try {
                circuitBreaker.checkState();
            } catch (CircuitBreaker.CircuitBreakerOpenException e) {
                logger.warnf("Circuit breaker is open, failing fast: %s", e.getMessage());
                throw new StatusListException("Circuit breaker is open: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Records a successful operation with the circuit breaker.
     */
    private void recordSuccess() {
        if (circuitBreaker != null) {
            circuitBreaker.recordSuccess();
        }
    }

    /**
     * Records a failed operation with the circuit breaker.
     */
    private void recordFailure() {
        if (circuitBreaker != null) {
            circuitBreaker.recordFailure();
        }
    }

    /**
     * Records a timeout with the circuit breaker.
     */
    private void recordTimeout() {
        if (circuitBreaker != null) {
            circuitBreaker.recordTimeout();
        }
    }
}
