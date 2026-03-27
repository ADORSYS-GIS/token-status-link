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
    private static final int DEFAULT_RETRY_COUNT = 1; // Enable one retry by default

    /**
     * Creates an HTTP client with timeout values from the configuration.
     * All callers must use this method so that timeouts are always taken from config.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    public static CloseableHttpClient getHttpClient(StatusListConfig config) {
        int timeoutMs = config.getIssuanceTimeout();
        if (timeoutMs <= 0) {
            timeoutMs = DEFAULT_CONNECT_TIMEOUT;
        }
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofMilliseconds(timeoutMs))
                .setResponseTimeout(Timeout.ofMilliseconds(timeoutMs))
                .build();
        return HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryStrategy(getHttpRequestRetryStrategy())
                .build();
    }

    private static HttpRequestRetryStrategy getHttpRequestRetryStrategy() {
        int maxRetries = DEFAULT_RETRY_COUNT;

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
