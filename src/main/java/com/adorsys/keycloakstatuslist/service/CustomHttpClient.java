package com.adorsys.keycloakstatuslist.service;

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

import java.io.IOException;

public class CustomHttpClient {

    private static final Logger logger = Logger.getLogger(CustomHttpClient.class);

    private static final int DEFAULT_CONNECT_TIMEOUT = 30000;
    private static final int DEFAULT_READ_TIMEOUT = 60000;
    private static final int DEFAULT_RETRY_COUNT = 0; // Retry disabled by default

    public static CloseableHttpClient getHttpClient() {
        RequestConfig requestConfig = getRequestConfig();
        HttpRequestRetryStrategy retryStrategy = getHttpRequestRetryStrategy();

        return HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryStrategy(retryStrategy)
                .build();
    }

    private static RequestConfig getRequestConfig() {
        Timeout connectTimeout = Timeout.ofMilliseconds(DEFAULT_CONNECT_TIMEOUT);
        Timeout responseTimeout = Timeout.ofMilliseconds(DEFAULT_READ_TIMEOUT);

        return RequestConfig.custom()
                .setConnectionRequestTimeout(connectTimeout)
                .setResponseTimeout(responseTimeout)
                .build();
    }

    private static HttpRequestRetryStrategy getHttpRequestRetryStrategy() {
        int maxRetries = DEFAULT_RETRY_COUNT;

        return new HttpRequestRetryStrategy() {
            @Override
            public boolean retryRequest(HttpRequest httpRequest, IOException e, int execCount, HttpContext httpContext) {
                logger.warnf("[Attempt %d/%d] Error sending status: %s", execCount, maxRetries, e.getMessage());
                return execCount <= maxRetries;
            }

            @Override
            public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
                logger.warnf("[Attempt %d/%d] Failed to send status to %s for idx %d: %d %s",
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
}
