package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpHost;
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

    @Test
    void resolveProxyShouldParseFromAllEnvVarCandidates() {
        String[] candidates = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"};
        for (String envVarName : candidates) {
            Map<String, String> env = new HashMap<>();
            env.put(envVarName, "http://squid-proxy.infra.svc.cluster.local:8888");

            HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

            assertNotNull(proxy, "Expected proxy for env var " + envVarName);
            assertEquals("http", proxy.getSchemeName());
            assertEquals("squid-proxy.infra.svc.cluster.local", proxy.getHostName());
            assertEquals(8888, proxy.getPort());
        }
    }

    @Test
    void resolveProxyShouldPreferHttpsOverHttp() {
        Map<String, String> env = new HashMap<>();
        env.put("HTTPS_PROXY", "http://https-proxy:3128");
        env.put("HTTP_PROXY", "http://http-proxy:8080");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals("https-proxy", proxy.getHostName());
        assertEquals(3128, proxy.getPort());
    }

    @Test
    void resolveProxyShouldReturnNullWhenNoEnvVarSet() {
        HttpHost proxy = CustomHttpClient.resolveProxy(name -> null);

        assertNull(proxy);
    }

    @Test
    void resolveProxyShouldDefaultPortForHttpScheme() {
        Map<String, String> env = Map.of("HTTP_PROXY", "http://proxy-host");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals(80, proxy.getPort());
    }

    @Test
    void resolveProxyShouldDefaultPortForHttpsScheme() {
        Map<String, String> env = Map.of("HTTPS_PROXY", "https://proxy-host");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals(443, proxy.getPort());
    }

    @Test
    void resolveProxyShouldReturnNullForInvalidUrl() {
        Map<String, String> env = Map.of("HTTPS_PROXY", "not a valid url ://");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNull(proxy);
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
