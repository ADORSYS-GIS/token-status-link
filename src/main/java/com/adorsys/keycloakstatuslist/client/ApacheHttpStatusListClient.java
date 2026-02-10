package com.adorsys.keycloakstatuslist.client;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;
import com.adorsys.keycloakstatuslist.util.HttpStatusCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.UUID;

/**
 * Apache HTTP Client implementation of StatusListHttpClient with circuit breaker support.
 */
public class ApacheHttpStatusListClient implements StatusListHttpClient {
    
    private static final Logger logger = Logger.getLogger(ApacheHttpStatusListClient.class);
    
    private static final String CREDENTIALS_PATH = "credentials";
    private static final String STATUS_LISTS_PATH = "statuslists";
    private static final String HEALTH_PATH = "health";
    
    private final String serverUrl;
    private final String authToken;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final CircuitBreaker circuitBreaker;
    
    /**
     * Creates a new Apache HTTP client for status list operations.
     *
     * @param serverUrl the status list server URL
     * @param authToken the authentication token
     * @param httpClient the HTTP client to use
     * @param circuitBreaker optional circuit breaker (can be null to disable)
     */
    public ApacheHttpStatusListClient(String serverUrl, String authToken, 
                                     CloseableHttpClient httpClient, 
                                     CircuitBreaker circuitBreaker) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl : serverUrl + "/";
        this.authToken = authToken;
        this.httpClient = httpClient;
        this.circuitBreaker = circuitBreaker;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        logger.infof("Initialized ApacheHttpStatusListClient with serverUrl: %s, circuitBreaker: %s",
                this.serverUrl, circuitBreaker != null ? "enabled" : "disabled");
    }
    
    @Override
    public void publishRecord(TokenStatusRecord statusRecord) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        String credentialId = statusRecord.getCredentialId();
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debugf("Request ID: %s, Publishing record for credentialId: %s", requestId, credentialId);
            
            HttpPost httpPost = new HttpPost(serverUrl + CREDENTIALS_PATH);
            configureJsonRequest(httpPost, requestId, jsonPayload);
            
            httpClient.execute(httpPost, response -> handleResponse(
                    response, requestId,
                    "Successfully published record for credentialId: " + credentialId,
                    "Failed to publish record for credentialId: " + credentialId,
                    true));
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout publishing record for credentialId: " + credentialId,
                    "Failed to publish record for credentialId: " + credentialId);
        }
    }
    
    @Override
    public void updateRecord(TokenStatusRecord statusRecord) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        String credentialId = statusRecord.getCredentialId();
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debugf("Request ID: %s, Updating record for credentialId: %s", requestId, credentialId);
            
            HttpPatch httpPatch = new HttpPatch(serverUrl + CREDENTIALS_PATH);
            configureJsonRequest(httpPatch, requestId, jsonPayload);
            
            httpClient.execute(httpPatch, response -> handleResponse(
                    response, requestId,
                    "Successfully updated record for credentialId: " + credentialId,
                    "Failed to update record for credentialId: " + credentialId,
                    false));
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout updating record for credentialId: " + credentialId,
                    "Failed to update record for credentialId: " + credentialId);
        }
    }
    
    @Override
    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        logger.infof("Request ID: %s, Registering issuer: %s with server: %s", requestId, issuerId, serverUrl);
        
        TokenStatusRecord issuerRecord = new TokenStatusRecord();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(issuerRecord);
            logger.debugf("Request ID: %s, Registering issuer: %s, Payload: %s", requestId, issuerId, jsonPayload);
            
            HttpPost httpPost = new HttpPost(serverUrl + CREDENTIALS_PATH);
            configureJsonRequest(httpPost, requestId, jsonPayload);
            
            httpClient.execute(httpPost, response -> {
                String responseHeaders = response.getHeaders().toString();
                logger.debugf("Request ID: %s, Received response: Status code: %d, Headers: %s, Body: %s", 
                        requestId, response.getCode(), responseHeaders, 
                        (response.getEntity() != null ? "present" : "empty"));
                
                handleResponse(response, requestId,
                        "Successfully registered issuer: " + issuerId,
                        "Failed to register issuer: " + issuerId,
                        true);
                return Boolean.TRUE;
            });
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout registering issuer: " + issuerId + ", Server URL: " + serverUrl,
                    "Failed to register issuer: " + issuerId + ", Server URL: " + serverUrl);
        }
    }
    
    @Override
    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking if status list exists: %s", requestId, statusListId);
        
        HttpGet httpGet = new HttpGet(serverUrl + STATUS_LISTS_PATH + "/" + statusListId);
        configureCommonHeaders(httpGet, requestId);
        
        try {
            return httpClient.execute(httpGet, response -> 
                    handleStatusListExistsResponse(response, requestId, statusListId));
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout checking status list " + statusListId,
                    "Error checking status list " + statusListId);
            return false;
        }
    }
    
    @Override
    public void publishStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();
        
        String listId = payload.listId();
        logger.debugf("Request ID: %s, Publishing new status list: %s", requestId, listId);
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPost httpPost = new HttpPost(serverUrl + STATUS_LISTS_PATH);
            configureJsonRequest(httpPost, requestId, jsonPayload);
            
            httpClient.execute(httpPost, response -> handleResponse(
                    response, requestId,
                    "Successfully published status list: " + listId,
                    "Failed to publish status list " + listId,
                    false));
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout publishing status list " + listId,
                    "Error publishing status list " + listId);
        }
    }
    
    @Override
    public void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();
        
        String listId = payload.listId();
        logger.debugf("Request ID: %s, Updating existing status list: %s", requestId, listId);
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(payload);
            HttpPatch httpPatch = new HttpPatch(serverUrl + STATUS_LISTS_PATH + "/" + listId);
            configureJsonRequest(httpPatch, requestId, jsonPayload);
            
            httpClient.execute(httpPatch, response -> handleResponse(
                    response, requestId,
                    "Successfully updated status list: " + listId,
                    "Failed to update status list " + listId,
                    false));
            
        } catch (IOException | StatusListServerException e) {
            handleException(e, requestId,
                    "Timeout updating status list " + listId,
                    "Error updating status list " + listId);
        }
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
                if (HttpStatusCode.isSuccess(statusCode)) {
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
    public String getStatusListUri(String listId) {
        return serverUrl + STATUS_LISTS_PATH + "/" + listId;
    }
    
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
    private Void handleResponse(ClassicHttpResponse response, String requestId, 
                                String successMessage, String errorMessagePrefix, 
                                boolean acceptConflict) {
        int statusCode = response.getCode();
        String responseBody;
        try {
            if (response.getEntity() != null) {
                responseBody = EntityUtils.toString(response.getEntity());
            } else {
                responseBody = "";
            }
        } catch (IOException | ParseException e) {
            responseBody = "Unable to read response body: " + e.getMessage();
        }
        
        boolean isSuccess = HttpStatusCode.isSuccess(statusCode) || 
                           (acceptConflict && statusCode == HttpStatusCode.CONFLICT.getCode());
        
        if (isSuccess) {
            String fullMessage = successMessage;
            if (acceptConflict && statusCode == HttpStatusCode.CONFLICT.getCode()) {
                fullMessage += " (already registered)";
            }
            logger.infof("Request ID: %s, %s", requestId, fullMessage);
            recordSuccess();
        } else {
            logger.errorf("Request ID: %s, %s. Status code: %d, Response: %s", 
                    requestId, errorMessagePrefix, statusCode, responseBody);
            recordFailure();
            throw new StatusListServerException(
                    errorMessagePrefix + ". Status code: " + statusCode, statusCode);
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
    private boolean handleStatusListExistsResponse(ClassicHttpResponse response, 
                                                  String requestId, String statusListId) {
        int statusCode = response.getCode();
        
        if (statusCode == HttpStatusCode.OK.getCode()) {
            logger.infof("Request ID: %s, Status list %s exists.", requestId, statusListId);
            recordSuccess();
            return true;
        } else if (statusCode == HttpStatusCode.NOT_FOUND.getCode()) {
            logger.infof("Request ID: %s, Status list %s does not exist.", requestId, statusListId);
            recordSuccess();
            return false;
        } else {
            String responseBody;
            try {
                if (response.getEntity() != null) {
                    responseBody = EntityUtils.toString(response.getEntity());
                } else {
                    responseBody = "";
                }
            } catch (IOException | ParseException e) {
                responseBody = "Unable to read response body: " + e.getMessage();
            }
            logger.errorf("Request ID: %s, Failed to check status list %s. Status code: %d, Response: %s", 
                    requestId, statusListId, statusCode, responseBody);
            recordFailure();
            throw new StatusListServerException(
                    "Failed to check status list " + statusListId + ". Status code: " + statusCode,
                    statusCode);
        }
    }
    
    /**
     * Handles IOException and StatusListServerException consistently across all HTTP operations.
     * 
     * @param e the exception to handle (IOException or StatusListServerException)
     * @param requestId the request ID for logging
     * @param timeoutMessage message for timeout exceptions
     * @param ioErrorMessage message for IO exceptions
     * @throws StatusListException for IOException cases
     * @throws StatusListServerException for StatusListServerException cases (rethrown directly)
     */
    private void handleException(Exception e, String requestId,
                                String timeoutMessage, String ioErrorMessage) 
            throws StatusListException, StatusListServerException {
        if (e instanceof StatusListServerException) {
            // StatusListServerException is already a domain exception, rethrow directly
            recordFailure();
            logger.errorf(e, "Request ID: %s, Server error: %s", requestId, e.getMessage());
            throw (StatusListServerException) e;
        }
        
        if (e instanceof IOException) {
            IOException ioException = (IOException) e;
            if (ioException instanceof InterruptedIOException) {
                Thread.currentThread().interrupt();
                recordTimeout();
                logger.errorf(ioException, "Request ID: %s, %s: %s", requestId, timeoutMessage, ioException.getMessage());
                throw new StatusListException(timeoutMessage, ioException);
            } else {
                recordFailure();
                logger.errorf(ioException, "Request ID: %s, %s: %s", requestId, ioErrorMessage, ioException.getMessage());
                throw new StatusListException(ioErrorMessage, ioException);
            }
        } else {
            recordFailure();
            logger.errorf(e, "Request ID: %s, Unexpected exception type: %s", requestId, e.getClass().getName());
            throw new StatusListException(ioErrorMessage, e);
        }
    }
    
    /**
     * Configures common headers (X-Request-ID and Authorization) for any HTTP request.
     * 
     * @param request the HTTP request to configure
     * @param requestId the request ID to set in the X-Request-ID header
     */
    private void configureCommonHeaders(org.apache.hc.core5.http.HttpRequest request, String requestId) {
        request.setHeader("X-Request-ID", requestId);
        if (authToken != null && !authToken.isEmpty()) {
            request.setHeader("Authorization", "Bearer " + authToken);
        }
    }
    
    /**
     * Configures a POST or PATCH request with JSON payload and common headers.
     * 
     * @param request the HTTP request to configure (HttpPost or HttpPatch)
     * @param requestId the request ID to set in the X-Request-ID header
     * @param jsonPayload the JSON payload to set as the request entity
     */
    private void configureJsonRequest(org.apache.hc.core5.http.HttpRequest request, String requestId, String jsonPayload) {
        request.setHeader("Content-Type", "application/json");
        configureCommonHeaders(request, requestId);
        if (request instanceof HttpPost) {
            ((HttpPost) request).setEntity(new StringEntity(jsonPayload));
        } else if (request instanceof HttpPatch) {
            ((HttpPatch) request).setEntity(new StringEntity(jsonPayload));
        }
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

