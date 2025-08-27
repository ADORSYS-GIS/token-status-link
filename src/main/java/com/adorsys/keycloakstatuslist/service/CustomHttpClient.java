package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.StatusListProtocolMapper;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
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

    public static CloseableHttpClient getHttpClient(StatusListConfig realmConfig) {
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
