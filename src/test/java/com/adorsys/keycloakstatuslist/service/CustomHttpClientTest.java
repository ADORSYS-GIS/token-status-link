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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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

    @Test
    void buildSslContextShouldReturnNullWhenNoTlsConfigured() {
        StatusListConfig config = configWithTls(false, null);

        SSLContext result = CustomHttpClient.buildSslContext(config);

        assertNull(result);
    }

    @Test
    void buildSslContextShouldReturnContextWhenTrustAllEnabled() {
        StatusListConfig config = configWithTls(true, null);

        SSLContext result = CustomHttpClient.buildSslContext(config);

        assertNotNull(result);
    }

    @Test
    void buildSslContextShouldReturnContextForValidCaCert(@TempDir Path tempDir) throws Exception {
        Path certFile = tempDir.resolve("ca.crt");
        Files.writeString(certFile, TEST_CA_PEM);

        StatusListConfig config = configWithTls(false, certFile.toString());

        SSLContext result = CustomHttpClient.buildSslContext(config);

        assertNotNull(result);
    }

    @Test
    void buildSslContextShouldFallBackToNullForMissingCaCertFile() {
        StatusListConfig config = configWithTls(false, "/nonexistent/ca.crt");

        SSLContext result = CustomHttpClient.buildSslContext(config);

        assertNull(result);
    }

    @Test
    void buildConnectionManagerShouldReturnNullWhenNoTlsConfigured() {
        StatusListConfig config = configWithTls(false, null);

        HttpClientConnectionManager result = CustomHttpClient.buildConnectionManager(config);

        assertNull(result);
    }

    @Test
    void buildConnectionManagerShouldReturnManagerWhenTrustAllEnabled() {
        StatusListConfig config = configWithTls(true, null);

        HttpClientConnectionManager result = CustomHttpClient.buildConnectionManager(config);

        assertNotNull(result);
    }

    private StatusListConfig configWithTls(boolean trustAll, String caCertPath) {
        RealmModel realm = mock(RealmModel.class);
        if (trustAll) {
            when(realm.getAttribute(StatusListConfig.STATUS_LIST_TLS_TRUST_ALL)).thenReturn("true");
        }
        if (caCertPath != null) {
            when(realm.getAttribute(StatusListConfig.STATUS_LIST_TLS_CA_CERT_PATH)).thenReturn(caCertPath);
        }
        return new StatusListConfig(realm);
    }

    private static final String TEST_CA_PEM =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIDBTCCAe2gAwIBAgIUZ0BfKEPgqHS63KWkX3pC3nuvvKEwDQYJKoZIhvcNAQEL\n"
                    + "BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA2MjUxMjA2MjZaFw0yNzA2MjUx\n"
                    + "MjA2MjZaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
                    + "DwAwggEKAoIBAQDuIObFSYy/zTWPFhPhaLh8Q8JKkJjCmpye04hYFg212FWSV9iS\n"
                    + "CkEIhEhsA9zm6hMzHAcBTCJ1hlM/CHJ7LA9bb0o4tO+lnP3a/kBEG7RPVD4f0run\n"
                    + "sSTjGFrci4SAWCu8RhNV7KH6jv+6315w6onSO6RPyUEzodKP8D0NE3aTasyKpaW1\n"
                    + "mn4dP+CrYnutHegQQNM+gxAqTbrL9ghMtt2cR//vOxaMSrL7N+IfTEu1qxVqeqU5\n"
                    + "pgUsUNG5XNAjhANU5zfhR3TmZWm3pjhiGu+kO5cFgjDYeEFwiqhzvxjyhs1RA89Z\n"
                    + "pvgbz5HtiAhEDrRH3nyiswzOjb8IcIrLxUO5AgMBAAGjUzBRMB0GA1UdDgQWBBQd\n"
                    + "05/+gyT8HVBAHZvC1vWbz87e8jAfBgNVHSMEGDAWgBQd05/+gyT8HVBAHZvC1vWb\n"
                    + "z87e8jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBOfXtezUxP\n"
                    + "CUFklnuon3No/st1Hff6KedmLAmtCDrELuhEMMHh3kINmMcnR2jyXadSO3FIjcc5\n"
                    + "VVTlj37g3+QRKJuFq18VNDnTT95ErzRPFQe4iBMcrxhNmuVJFx2TIgMtQUEljFJe\n"
                    + "OlrsqzyPkJ39NIN8n7EAg7a5fIMe+lf0bm+VzsQ0i9O0BRFF5kB1lZbOh2n2rJtJ\n"
                    + "6tvSzFaVh+YFMGhbspX5roRHFmM4IwiPSW8egEBSa6FkUY1kbLuo8sIBCwASmWBb\n"
                    + "YQKr1usSnpXvftbJyMKGEFFfLYlQz8NxwgO+QBk2HH2WuNffKU7bf4lChsX6fPmk\n"
                    + "zwk6Xo03geo5\n"
                    + "-----END CERTIFICATE-----\n";

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
