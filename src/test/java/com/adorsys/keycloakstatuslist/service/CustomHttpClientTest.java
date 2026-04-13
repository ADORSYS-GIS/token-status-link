package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import java.io.IOException;
import java.lang.reflect.Method;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

class CustomHttpClientTest {

    @Test
    void shouldCreateHttpClientWithConfiguredTimeout() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT)).thenReturn("5000");
        StatusListConfig config = new StatusListConfig(realm);

        try (CloseableHttpClient client = CustomHttpClient.getHttpClient(config)) {
            assertNotNull(client);
        }
    }

    @Test
    void shouldCreateHttpClientWithDefaultTimeoutWhenConfiguredValueIsNonPositive() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT)).thenReturn("0");
        StatusListConfig config = new StatusListConfig(realm);

        try (CloseableHttpClient client = CustomHttpClient.getHttpClient(config)) {
            assertNotNull(client);
        }
    }

    @Test
    void retryStrategyShouldNotRetryIOExceptionWhenRetriesDisabled() {
        HttpRequestRetryStrategy strategy = getRetryStrategy(0);

        boolean shouldRetry = strategy.retryRequest(
                mock(HttpRequest.class), new IOException("network error"), 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryStrategyShouldNotRetryServerErrorsWhenRetriesDisabled() {
        HttpRequestRetryStrategy strategy = getRetryStrategy(0);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getCode()).thenReturn(503);
        when(response.getReasonPhrase()).thenReturn("Service Unavailable");

        boolean shouldRetry = strategy.retryRequest(response, 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryStrategyShouldNotRetryClientErrors() {
        HttpRequestRetryStrategy strategy = getRetryStrategy(3);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getCode()).thenReturn(400);

        boolean shouldRetry = strategy.retryRequest(response, 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryIntervalShouldUseExponentialBackoff() {
        HttpRequestRetryStrategy strategy = getRetryStrategy(3);
        HttpContext context = mock(HttpContext.class);
        HttpResponse response = mock(HttpResponse.class);

        TimeValue first = strategy.getRetryInterval(response, 1, context);
        TimeValue third = strategy.getRetryInterval(response, 3, context);

        assertEquals(TimeValue.ofSeconds(1), first);
        assertEquals(TimeValue.ofSeconds(4), third);
    }

    private HttpRequestRetryStrategy getRetryStrategy(int maxRetries) {
        try {
            Method method = CustomHttpClient.class.getDeclaredMethod("getHttpRequestRetryStrategy", int.class);
            method.setAccessible(true);
            return (HttpRequestRetryStrategy) method.invoke(null, maxRetries);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to access retry strategy", e);
        }
    }
}
