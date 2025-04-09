package com.adorsys.keycloakstatuslist.service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Service responsible for publishing token status to the status list server.
 */
public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final StatusListConfig config;
    
    public StatusListService(StatusListConfig config) {
        this.config = config;
    }

    /**
     * Publishes token status to the status list server.
     * 
     * @param tokenStatus the token status to publish
     * @return true if publishing was successful, false otherwise
     */
    public boolean publishTokenStatus(TokenStatus tokenStatus) {
        if (!config.isEnabled()) {
            logger.debug("Status list service is disabled. Skipping token status publication.");
            return false;
        }
        
        logger.debug("Publishing token status: " + tokenStatus);
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.of(config.getConnectTimeout(), TimeUnit.MILLISECONDS))
                .setResponseTimeout(Timeout.of(config.getReadTimeout(), TimeUnit.MILLISECONDS))
                .build();
                
        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {
            
            HttpPost httpPost = new HttpPost(config.getServerUrl());
            httpPost.setHeader("Content-Type", "application/json");
            
            // Add authorization if configured
            String authToken = config.getAuthToken();
            if (authToken != null && !authToken.isEmpty()) {
                httpPost.setHeader("Authorization", "Bearer " + authToken);
            }
            
            // Convert token status to JSON
            String jsonPayload = objectMapper.writeValueAsString(tokenStatus);
            httpPost.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON));
            
            // Execute request with retry logic
            return executeWithRetry(httpClient, httpPost);
            
        } catch (Exception e) {
            logger.error("Failed to publish token status: " + e.getMessage(), e);
            return false;
        }
    }
    
    private boolean executeWithRetry(CloseableHttpClient httpClient, HttpPost httpPost) throws IOException {
        int retryCount = config.getRetryCount();
        int attempt = 0;
        
        while (attempt <= retryCount) {
            try {
                attempt++;
                logger.debug("Publishing token status attempt " + attempt);
                
                try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                    int statusCode = response.getCode();
                    
                    if (statusCode >= 200 && statusCode < 300) {
                        logger.debug("Token status published successfully. Status code: " + statusCode);
                        return true;
                    } else {
                        logger.warn("Failed to publish token status. Status code: " + statusCode);
                        if (attempt > retryCount || !isRetryable(statusCode)) {
                            return false;
                        }
                    }
                }
                
                // Exponential backoff
                long backoffTime = (long) Math.pow(2, attempt) * 100;
                Thread.sleep(backoffTime);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("Thread interrupted during retry wait", e);
                return false;
            } catch (IOException e) {
                logger.error("I/O error during status publication attempt " + attempt, e);
                if (attempt > retryCount) {
                    throw e;
                }
                
                try {
                    // Simple backoff for I/O errors
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        
        return false;
    }
    
    private boolean isRetryable(int statusCode) {
        // Don't retry on client errors except for 429 (too many requests)
        return statusCode == 429 || statusCode >= 500;
    }
}