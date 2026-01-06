package com.adorsys.keycloakstatuslist.client;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
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
            logger.debug("Request ID: " + requestId + ", Publishing record for credentialId: " + credentialId);
            
            HttpPost httpPost = new HttpPost(serverUrl + "credentials");
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("X-Request-ID", requestId);
            httpPost.setEntity(new StringEntity(jsonPayload));
            
            if (authToken != null && !authToken.isEmpty()) {
                httpPost.setHeader("Authorization", "Bearer " + authToken);
            }
            
            httpClient.execute(httpPost, response -> {
                int statusCode = response.getCode();
                String responseBody = EntityUtils.toString(response.getEntity());
                if (statusCode >= 200 && statusCode < 300 || statusCode == 409) {
                    logger.info("Request ID: " + requestId + ", Successfully published record for credentialId: "
                            + credentialId +
                            (statusCode == 409 ? " (already registered)" : ""));
                    recordSuccess();
                    return null;
                } else {
                    logger.error("Request ID: " + requestId + ", Failed to publish record for credentialId: "
                            + credentialId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to publish record for credentialId: " + credentialId + ". Status code: "
                                    + statusCode,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout publishing record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Timeout publishing record for credentialId: " + credentialId, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Failed to publish record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Failed to publish record for credentialId: " + credentialId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error publishing record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error publishing record for credentialId: " + credentialId, e);
        }
    }
    
    @Override
    public void updateRecord(TokenStatusRecord statusRecord) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        String credentialId = statusRecord.getCredentialId();
        
        try {
            String jsonPayload = objectMapper.writeValueAsString(statusRecord);
            logger.debug("Request ID: " + requestId + ", Updating record for credentialId: " + credentialId);
            
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
                    logger.info("Request ID: " + requestId + ", Successfully updated record for credentialId: " + credentialId);
                    recordSuccess();
                    return null;
                } else {
                    logger.error("Request ID: " + requestId + ", Failed to update record for credentialId: " + credentialId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to update record for credentialId: " + credentialId + ". Status code: " + statusCode,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout updating record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Timeout updating record for credentialId: " + credentialId, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Failed to update record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Failed to update record for credentialId: " + credentialId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error updating record for credentialId: " + credentialId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error updating record for credentialId: " + credentialId, e);
        }
    }
    
    @Override
    public void registerIssuer(String issuerId, JWK publicKey) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        logger.info("Request ID: " + requestId + ", Registering issuer: " + issuerId + " with server: " + serverUrl);
        
        TokenStatusRecord issuerRecord = new TokenStatusRecord();
        issuerRecord.setIssuer(issuerId);
        issuerRecord.setPublicKey(publicKey);
        
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
                    recordSuccess();
                    return Boolean.TRUE;
                } else {
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to register issuer: " + issuerId +
                                    ", Status code: " + statusCode +
                                    ", Response: " + responseBody,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout registering issuer: " + issuerId +
                    ": " + e.getMessage() + ", Server URL: " + serverUrl, e);
            throw new StatusListException("Timeout registering issuer: " + issuerId +
                    ", Server URL: " + serverUrl, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Failed to register issuer: " + issuerId +
                    ": " + e.getMessage() + ", Server URL: " + serverUrl, e);
            throw new StatusListException("Failed to register issuer: " + issuerId +
                    ", Server URL: " + serverUrl, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error registering issuer: " + issuerId +
                    ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error registering issuer: " + issuerId, e);
        }
    }
    
    @Override
    public boolean checkStatusListExists(String statusListId) throws StatusListException {
        checkCircuitBreaker();
        
        String requestId = UUID.randomUUID().toString();
        logger.debug("Request ID: " + requestId + ", Checking if status list exists: " + statusListId);
        
        HttpGet httpGet = new HttpGet(serverUrl + "statuslists/" + statusListId);
        httpGet.setHeader("X-Request-ID", requestId);
        
        try {
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                if (statusCode == 200) {
                    logger.info("Request ID: " + requestId + ", Status list " + statusListId + " exists.");
                    recordSuccess();
                    return true;
                } else if (statusCode == 404) {
                    logger.info("Request ID: " + requestId + ", Status list " + statusListId + " does not exist.");
                    recordSuccess();
                    return false;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to check status list " + statusListId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to check status list " + statusListId + ". Status code: " + statusCode,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout checking status list " + statusListId + ": " + e.getMessage(), e);
            throw new StatusListException("Timeout checking status list " + statusListId, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Error checking status list " + statusListId + ": " + e.getMessage(), e);
            throw new StatusListException("Error checking status list " + statusListId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error checking status list " + statusListId + ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error checking status list " + statusListId, e);
        }
    }
    
    @Override
    public void publishStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();
        
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
                    recordSuccess();
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to publish status list " + listId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to publish status list " + listId + ". Status code: " + statusCode,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout publishing status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Timeout publishing status list " + listId, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Error publishing status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Error publishing status list " + listId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error publishing status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error publishing status list " + listId, e);
        }
    }
    
    @Override
    public void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException {
        checkCircuitBreaker();
        
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
                    recordSuccess();
                    return null;
                } else {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    logger.error("Request ID: " + requestId + ", Failed to update status list " + listId +
                            ". Status code: " + statusCode + ", Response: " + responseBody);
                    recordFailure();
                    throw new IllegalStateException(new StatusListServerException(
                            "Failed to update status list " + listId + ". Status code: " + statusCode,
                            statusCode));
                }
            });
            
        } catch (InterruptedIOException e) {
            recordTimeout();
            logger.error("Request ID: " + requestId + ", Timeout updating status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Timeout updating status list " + listId, e);
        } catch (IOException e) {
            recordFailure();
            logger.error("Request ID: " + requestId + ", Error updating status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Error updating status list " + listId, e);
        } catch (Exception e) {
            if (e.getCause() instanceof StatusListServerException serverException) {
                throw serverException;
            }
            recordFailure();
            logger.error("Request ID: " + requestId + ", Unexpected error updating status list " + listId + ": " + e.getMessage(), e);
            throw new StatusListException("Unexpected error updating status list " + listId, e);
        }
    }
    
    @Override
    public boolean checkServerHealth() {
        String requestId = UUID.randomUUID().toString();
        logger.debugf("Request ID: %s, Checking server health at: %s", requestId, serverUrl);
        
        HttpGet httpGet = new HttpGet(this.serverUrl + "health");
        httpGet.setHeader("X-Request-ID", requestId);
        
        try {
            // Don't check circuit breaker for health checks
            return httpClient.execute(httpGet, response -> {
                int statusCode = response.getCode();
                if (statusCode >= 200 && statusCode < 300) {
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
    
    /**
     * Checks the circuit breaker state before allowing a request.
     */
    private void checkCircuitBreaker() throws StatusListException {
        if (circuitBreaker != null) {
            try {
                circuitBreaker.checkState();
            } catch (CircuitBreaker.CircuitBreakerOpenException e) {
                logger.warn("Circuit breaker is open, failing fast: " + e.getMessage());
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

