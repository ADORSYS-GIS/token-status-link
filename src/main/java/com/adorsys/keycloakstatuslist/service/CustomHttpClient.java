package com.adorsys.keycloakstatuslist.service;

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

    private static final int DEFAULT_CONNECT_TIMEOUT = 30000;
    private static final int DEFAULT_READ_TIMEOUT = 60000;

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
        logger.debug("HTTP retries disabled for status list communication.");
        return new HttpRequestRetryStrategy() {
            @Override
            public boolean retryRequest(
                    HttpRequest httpRequest, IOException e, int execCount, HttpContext httpContext) {
                return false;
            }

            @Override
            public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
                return false;
            }

            @Override
            public TimeValue getRetryInterval(
                    HttpResponse httpResponse, int execCount, HttpContext httpContext) {
                return TimeValue.ZERO_MILLISECONDS;
            }
        };
    }
}
