package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import java.io.IOException;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

public class CustomHttpClient {

    private static final Logger logger = Logger.getLogger(CustomHttpClient.class);

    public static final int DEFAULT_CONNECT_TIMEOUT = 30000;

    /**
     * Creates an HTTP client for issuance operations (runtime/foreground).
     * Typically has a shorter timeout and fewer/no retries to protect tail latency.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    public static CloseableHttpClient getIssuanceHttpClient(StatusListConfig config) {
        // Issuance path: minimal/no retries to avoid blocking the user thread for too long
        return createHttpClient(config.getIssuanceTimeout(), 0);
    }

    /**
     * Creates an HTTP client for registration operations (background).
     * Can have longer timeouts and more retries since it doesn't block user threads.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    public static CloseableHttpClient getRegistrationHttpClient(StatusListConfig config) {
        return createHttpClient(config.getRegistrationTimeout(), config.getRegistrationRetries());
    }

    /**
     * Legacy method for backward compatibility - defaults to issuance policy.
     */
    public static CloseableHttpClient getHttpClient(StatusListConfig config) {
        return getIssuanceHttpClient(config);
    }

    private static CloseableHttpClient createHttpClient(int timeoutMs, int maxRetries) {
        if (timeoutMs <= 0) {
            timeoutMs = DEFAULT_CONNECT_TIMEOUT;
        }
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofMilliseconds(timeoutMs))
                .setResponseTimeout(Timeout.ofMilliseconds(timeoutMs))
                .build();
        return HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryStrategy(getHttpRequestRetryStrategy(maxRetries))
                .build();
    }

    private static HttpRequestRetryStrategy getHttpRequestRetryStrategy(int maxRetries) {
        return new HttpRequestRetryStrategy() {
            @Override
            public boolean retryRequest(
                    HttpRequest httpRequest, IOException e, int execCount, HttpContext httpContext) {
                logger.warnf("[Attempt %d/%d] Error sending status: %s", execCount, maxRetries, e.getMessage());
                return execCount <= maxRetries;
            }

            @Override
            public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
                int status = response.getCode();
                Boolean isRetriable = status >= 500;
                if (isRetriable) {
                    logger.warnf(
                            "[Attempt %d/%d] Failed to send status. Response: %d %s",
                            execCount, maxRetries, status, response.getReasonPhrase());
                }
                return execCount <= maxRetries && isRetriable;
            }

            @Override
            public TimeValue getRetryInterval(HttpResponse httpResponse, int execCount, HttpContext httpContext) {
                // Exponential backoff: 1s, 2s, 4s
                return TimeValue.ofSeconds((long) Math.pow(2, execCount - 1));
            }
        };
    }
}
