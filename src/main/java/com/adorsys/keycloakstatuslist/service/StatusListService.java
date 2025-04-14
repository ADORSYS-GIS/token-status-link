package com.adorsys.keycloakstatuslist.service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

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
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class StatusListService {
    private static final Logger logger = Logger.getLogger(StatusListService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    private final StatusListConfig config;

    public StatusListService(StatusListConfig config) {
        this.config = config;
    }

    /**
     * Publishes a new token status to the status list server (POST).
     */
    public boolean publishTokenStatus(TokenStatus tokenStatus) {
        if (!config.isEnabled()) {
            logger.debug("Status list service is disabled. Skipping token status publication.");
            return false;
        }

        logger.debug("Publishing token status: " + tokenStatus);
        return executeRequest(new HttpPost(config.getServerUrl()), tokenStatus);
    }

    /**
     * Updates an existing token status on the status list server (PUT).
     */
    public boolean updateTokenStatus(TokenStatus tokenStatus) {
        if (!config.isEnabled()) {
            logger.debug("Status list service is disabled. Skipping token status update.");
            return false;
        }

        logger.debug("Updating token status: " + tokenStatus);
        String updateUrl = config.getServerUrl() + "/" + tokenStatus.getTokenId();
        return executeRequest(new HttpPut(updateUrl), tokenStatus);
    }

    /**
     * Common method to execute HTTP requests with retry logic.
     */
    private boolean executeRequest(org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request, TokenStatus tokenStatus) {
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

            String jsonPayload = objectMapper.writeValueAsString(tokenStatus);
            request.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON));

            return executeWithRetry(httpClient, request);

        } catch (Exception e) {
            logger.error("Failed to execute request: " + e.getMessage(), e);
            return false;
        }
    }

    private boolean executeWithRetry(CloseableHttpClient httpClient, org.apache.hc.client5.http.classic.methods.HttpUriRequestBase request) throws IOException {
        int retryCount = config.getRetryCount();
        int attempt = 0;

        while (attempt <= retryCount) {
            try { 
                attempt++;
                logger.debug("Attempt " + attempt + " for " + request.getMethod() + " request");

                try (CloseableHttpResponse response = httpClient.execute(request)) {
                    int statusCode = response.getCode();

                    if (statusCode >= 200 && statusCode < 300) {
                        logger.debug("Request successful. Status code: " + statusCode);
                        return true;
                    } else {
                        logger.warn("Request failed. Status code: " + statusCode);
                        if (attempt > retryCount || !isRetryable(statusCode)) {
                            return false;
                        }
                    }
                }

                long backoffTime = (long) Math.pow(2, attempt) * 100;
                Thread.sleep(backoffTime);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("Thread interrupted during retry wait", e);
                return false;
            } catch (IOException e) {
                logger.error("I/O error during attempt " + attempt, e);
                if (attempt > retryCount) {
                    throw e;
                }

                try {
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
        return statusCode == 429 || statusCode >= 500;
    }
}