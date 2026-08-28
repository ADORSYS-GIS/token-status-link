package io.github.adorsysgis.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
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
    void retryStrategyShouldNotRetryIOExceptionWhenRetriesDisabled() throws ReflectiveOperationException {
        HttpRequestRetryStrategy strategy = getRetryStrategy(0);

        boolean shouldRetry = strategy.retryRequest(
                mock(HttpRequest.class), new IOException("network error"), 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryStrategyShouldNotRetryServerErrorsWhenRetriesDisabled() throws ReflectiveOperationException {
        HttpRequestRetryStrategy strategy = getRetryStrategy(0);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getCode()).thenReturn(503);
        when(response.getReasonPhrase()).thenReturn("Service Unavailable");

        boolean shouldRetry = strategy.retryRequest(response, 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryStrategyShouldNotRetryClientErrors() throws ReflectiveOperationException {
        HttpRequestRetryStrategy strategy = getRetryStrategy(3);
        HttpResponse response = mock(HttpResponse.class);
        when(response.getCode()).thenReturn(400);

        boolean shouldRetry = strategy.retryRequest(response, 1, mock(HttpContext.class));

        assertFalse(shouldRetry);
    }

    @Test
    void retryIntervalShouldUseExponentialBackoff() throws ReflectiveOperationException {
        HttpRequestRetryStrategy strategy = getRetryStrategy(3);
        HttpContext context = mock(HttpContext.class);
        HttpResponse response = mock(HttpResponse.class);

        TimeValue first = strategy.getRetryInterval(response, 1, context);
        TimeValue third = strategy.getRetryInterval(response, 3, context);

        assertEquals(TimeValue.ofSeconds(1), first);
        assertEquals(TimeValue.ofSeconds(4), third);
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"})
    void resolveProxyShouldParseFromAllEnvVarCandidates(String envVarName) {
        Map<String, String> env = Map.of(envVarName, "http://squid-proxy.infra.svc.cluster.local:8888");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals("http", proxy.getSchemeName());
        assertEquals("squid-proxy.infra.svc.cluster.local", proxy.getHostName());
        assertEquals(8888, proxy.getPort());
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
    void resolveProxyShouldPreferUppercaseOverLowercaseEnvVar() {
        Map<String, String> env = new HashMap<>();
        env.put("HTTPS_PROXY", "http://upper-proxy:3128");
        env.put("https_proxy", "http://lower-proxy:3128");

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals("upper-proxy", proxy.getHostName());
    }

    @Test
    void resolveProxyShouldReturnNullWhenNoEnvVarSet() {
        assertNull(CustomHttpClient.resolveProxy(name -> null));
    }

    @ParameterizedTest
    @CsvSource({
        "http://proxy-host, 80",
        "https://proxy-host, 443",
    })
    void resolveProxyShouldApplyDefaultPortForScheme(String proxyUrl, int expectedPort) {
        Map<String, String> env = Map.of("HTTPS_PROXY", proxyUrl);

        HttpHost proxy = CustomHttpClient.resolveProxy(env::get);

        assertNotNull(proxy);
        assertEquals(expectedPort, proxy.getPort());
    }

    @ParameterizedTest
    @ValueSource(strings = {"not a valid url ://", "   ", "http://"})
    void resolveProxyShouldReturnNullForUnusableProxyUrl(String proxyUrl) {
        Map<String, String> env = Map.of("HTTPS_PROXY", proxyUrl);

        assertNull(CustomHttpClient.resolveProxy(env::get));
    }

    @Test
    void resolveNoProxyShouldParsePatterns() {
        Map<String, String> env = Map.of("NO_PROXY", "localhost,.example.com,internal.corp");

        List<String> patterns = CustomHttpClient.resolveNoProxy(env::get);

        assertEquals(List.of("localhost", ".example.com", "internal.corp"), patterns);
    }

    @Test
    void resolveNoProxyShouldPreferUppercaseOverLowercaseEnvVar() {
        Map<String, String> env = new HashMap<>();
        env.put("NO_PROXY", "upper.com");
        env.put("no_proxy", "lower.com");

        assertEquals(List.of("upper.com"), CustomHttpClient.resolveNoProxy(env::get));
    }

    @Test
    void resolveNoProxyShouldFallBackToLowercaseEnvVar() {
        Map<String, String> env = Map.of("no_proxy", "fallback.com");

        assertEquals(List.of("fallback.com"), CustomHttpClient.resolveNoProxy(env::get));
    }

    @Test
    void resolveNoProxyShouldReturnEmptyListWhenNoEnvVarSet() {
        assertTrue(CustomHttpClient.resolveNoProxy(name -> null).isEmpty());
    }

    @Test
    void resolveNoProxyShouldTrimWhitespaceAndSkipEmptyEntries() {
        Map<String, String> env = Map.of("NO_PROXY", " host1 , , host2 ");

        assertEquals(List.of("host1", "host2"), CustomHttpClient.resolveNoProxy(env::get));
    }

    @Test
    void resolveNoProxyShouldLowercasePatterns() {
        Map<String, String> env = Map.of("NO_PROXY", "MyHost.Example.COM");

        assertEquals(List.of("myhost.example.com"), CustomHttpClient.resolveNoProxy(env::get));
    }

    @ParameterizedTest
    @CsvSource({
        "api.example.com, .example.com, true",
        "example.com, .example.com, true",
        "notexample.com, .example.com, false",
        "api.example.com, example.com, true",
        "example.com, example.com, true",
        "notexample.com, example.com, false",
        "anything.at.all, *, true",
        "localhost, localhost, true",
        "UPPER.EXAMPLE.COM, example.com, true",
        "127.0.0.1, 127.0.0.1, true",
        "10.0.0.1, 127.0.0.1, false",
    })
    void isNoProxyHostShouldMatchCorrectly(String hostname, String pattern, boolean expected) {
        assertEquals(expected, CustomHttpClient.isNoProxyHost(hostname, List.of(pattern)));
    }

    @Test
    void isNoProxyHostShouldReturnFalseForEmptyPatterns() {
        assertFalse(CustomHttpClient.isNoProxyHost("example.com", List.of()));
    }

    @Test
    void buildSslContextShouldReturnNullWhenNoTlsConfigured() {
        assertNull(CustomHttpClient.buildSslContext(configWithTls(false, null)));
    }

    @Test
    void buildSslContextShouldReturnContextWhenTrustAllEnabled() {
        assertNotNull(CustomHttpClient.buildSslContext(configWithTls(true, null)));
    }

    @Test
    void buildSslContextShouldReturnContextForValidCaCert(@TempDir Path tempDir) throws Exception {
        Path certFile = tempDir.resolve("ca.crt");
        Files.writeString(certFile, TEST_CA_PEM);

        SSLContext result = CustomHttpClient.buildSslContext(configWithTls(false, certFile.toString()));

        assertNotNull(result);
    }

    @Test
    void buildSslContextShouldFallBackToJvmDefaultsForMissingCaCertFile() {
        assertNull(CustomHttpClient.buildSslContext(configWithTls(false, "/nonexistent/ca.crt")));
    }

    @Test
    void buildConnectionManagerShouldReturnNullWhenNoTlsConfigured() {
        assertNull(CustomHttpClient.buildConnectionManager(configWithTls(false, null)));
    }

    @Test
    void buildConnectionManagerShouldReturnManagerWhenTrustAllEnabled() {
        HttpClientConnectionManager result = CustomHttpClient.buildConnectionManager(configWithTls(true, null));

        assertNotNull(result);
    }

    private StatusListConfig configWithTls(boolean trustAll, String caCertPath) {
        RealmModel realm = mock(RealmModel.class);
        if (trustAll) {
            when(realm.getAttribute(StatusListConfig.STATUS_LIST_TLS_TRUST_ALL)).thenReturn("true");
        }
        if (caCertPath != null) {
            when(realm.getAttribute(StatusListConfig.STATUS_LIST_TLS_CA_CERT_PATH))
                    .thenReturn(caCertPath);
        }
        return new StatusListConfig(realm);
    }

    private static final String TEST_CA_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDBTCCAe2gAwIBAgIUZ0BfKEPgqHS63KWkX3pC3nuvvKEwDQYJKoZIhvcNAQEL
            BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA2MjUxMjA2MjZaFw0yNzA2MjUx
            MjA2MjZaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
            DwAwggEKAoIBAQDuIObFSYy/zTWPFhPhaLh8Q8JKkJjCmpye04hYFg212FWSV9iS
            CkEIhEhsA9zm6hMzHAcBTCJ1hlM/CHJ7LA9bb0o4tO+lnP3a/kBEG7RPVD4f0run
            sSTjGFrci4SAWCu8RhNV7KH6jv+6315w6onSO6RPyUEzodKP8D0NE3aTasyKpaW1
            mn4dP+CrYnutHegQQNM+gxAqTbrL9ghMtt2cR//vOxaMSrL7N+IfTEu1qxVqeqU5
            pgUsUNG5XNAjhANU5zfhR3TmZWm3pjhiGu+kO5cFgjDYeEFwiqhzvxjyhs1RA89Z
            pvgbz5HtiAhEDrRH3nyiswzOjb8IcIrLxUO5AgMBAAGjUzBRMB0GA1UdDgQWBBQd
            05/+gyT8HVBAHZvC1vWbz87e8jAfBgNVHSMEGDAWgBQd05/+gyT8HVBAHZvC1vWb
            z87e8jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBOfXtezUxP
            CUFklnuon3No/st1Hff6KedmLAmtCDrELuhEMMHh3kINmMcnR2jyXadSO3FIjcc5
            VVTlj37g3+QRKJuFq18VNDnTT95ErzRPFQe4iBMcrxhNmuVJFx2TIgMtQUEljFJe
            OlrsqzyPkJ39NIN8n7EAg7a5fIMe+lf0bm+VzsQ0i9O0BRFF5kB1lZbOh2n2rJtJ
            6tvSzFaVh+YFMGhbspX5roRHFmM4IwiPSW8egEBSa6FkUY1kbLuo8sIBCwASmWBb
            YQKr1usSnpXvftbJyMKGEFFfLYlQz8NxwgO+QBk2HH2WuNffKU7bf4lChsX6fPmk
            zwk6Xo03geo5
            -----END CERTIFICATE-----
            """;

    private HttpRequestRetryStrategy getRetryStrategy(int maxRetries) throws ReflectiveOperationException {
        Method method = CustomHttpClient.class.getDeclaredMethod("getHttpRequestRetryStrategy", int.class);
        method.setAccessible(true);
        return (HttpRequestRetryStrategy) method.invoke(null, maxRetries);
    }
}
