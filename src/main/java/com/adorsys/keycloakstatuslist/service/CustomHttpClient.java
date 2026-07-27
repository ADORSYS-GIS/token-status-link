package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;

public class CustomHttpClient {

    private static final Logger logger = Logger.getLogger(CustomHttpClient.class);

    private static final String[] PROXY_VARS = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"};
    private static final String[] NO_PROXY_VARS = {"NO_PROXY", "no_proxy"};

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
        return createHttpClient(config.getIssuanceTimeout(), 0, config);
    }

    /**
     * Creates an HTTP client for registration operations (background).
     * Can have longer timeouts and more retries since it doesn't block user threads.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    public static CloseableHttpClient getRegistrationHttpClient(StatusListConfig config) {
        return createHttpClient(config.getRegistrationTimeout(), config.getRegistrationRetries(), config);
    }

    /**
     * Legacy method for backward compatibility - defaults to issuance policy.
     */
    public static CloseableHttpClient getHttpClient(StatusListConfig config) {
        return getIssuanceHttpClient(config);
    }

    private static CloseableHttpClient createHttpClient(int timeoutMs, int maxRetries, StatusListConfig config) {
        if (timeoutMs <= 0) {
            timeoutMs = DEFAULT_CONNECT_TIMEOUT;
        }
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofMilliseconds(timeoutMs))
                .setResponseTimeout(Timeout.ofMilliseconds(timeoutMs))
                .build();
        HttpClientBuilder builder = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryStrategy(getHttpRequestRetryStrategy(maxRetries));

        // support usage of a http proxy - reuses the standard keycloak proxy/no-proxy env-vars
        HttpHost proxy = resolveProxy();
        if (proxy != null) {
            logger.infof("Using HTTP proxy: %s", proxy);
            List<String> noProxyPatterns = resolveNoProxy();
            if (noProxyPatterns.isEmpty()) {
                builder.setProxy(proxy);
            } else {
                builder.setRoutePlanner(new NoProxyAwareRoutePlanner(proxy, noProxyPatterns));
                logger.infof("NO_PROXY patterns: %s", noProxyPatterns);
            }
        }

        HttpClientConnectionManager connectionManager = buildConnectionManager(config);
        if (connectionManager != null) {
            builder.setConnectionManager(connectionManager);
        }

        return builder.build();
    }

    /**
     * Builds a connection manager with custom TLS configuration if needed.
     *
     * @param config the status list configuration containing TLS settings
     * @return a configured connection manager, or null to use the default
     */
    static HttpClientConnectionManager buildConnectionManager(StatusListConfig config) {
        SSLContext sslContext = buildSslContext(config);
        if (sslContext == null) {
            return null;
        }

        SSLConnectionSocketFactoryBuilder sslSocketBuilder =
                SSLConnectionSocketFactoryBuilder.create().setSslContext(sslContext);

        if (config.isTlsTrustAll()) {
            sslSocketBuilder.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketBuilder.build())
                .build();
    }

    /**
     * Builds an SSLContext based on the TLS configuration.
     * Returns null when the default JVM trust store should be used.
     *
     * @param config the status list configuration
     * @return a custom SSLContext, or null for JVM defaults
     */
    static SSLContext buildSslContext(StatusListConfig config) {
        try {
            if (config.isTlsTrustAll()) {
                logger.warn("TLS trust-all is enabled — all server certificates will be accepted");
                return SSLContextBuilder.create()
                        .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                        .build();
            }

            String caCertPath = config.getTlsCaCertPath();
            if (caCertPath != null && !caCertPath.isEmpty()) {
                logger.infof("Loading custom CA certificate from: %s", caCertPath);
                return buildSslContextFromCaCert(caCertPath);
            }
        } catch (Exception e) {
            logger.errorf(e, "Failed to build custom SSLContext, falling back to JVM defaults");
        }
        return null;
    }

    /**
     * Builds an SSLContext that trusts a specific PEM-encoded CA certificate file.
     *
     * @param caCertPath path to the PEM-encoded CA certificate
     * @return configured SSLContext
     * @throws Exception if the certificate cannot be loaded or the SSLContext cannot be built
     */
    static SSLContext buildSslContextFromCaCert(String caCertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert;
        try (FileInputStream fis = new FileInputStream(caCertPath)) {
            caCert = (X509Certificate) cf.generateCertificate(fis);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("status-list-ca", caCert);

        return SSLContextBuilder.create()
                .loadTrustMaterial(trustStore, null)
                .build();
    }

    /**
     * Resolves an HTTP proxy from the HTTPS_PROXY or HTTP_PROXY environment variables.
     * Apache HttpClient 5 does not read these variables automatically.
     *
     * @return the proxy HttpHost, or null if no proxy is configured
     */
    static HttpHost resolveProxy() {
        return resolveProxy(System::getenv);
    }

    /**
     * Resolves an HTTP proxy using the provided environment variable lookup function.
     * Checks HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy in order.
     *
     * @param envLookup function to look up environment variable values by name
     * @return the proxy HttpHost, or null if no proxy is configured
     */
    static HttpHost resolveProxy(Function<String, String> envLookup) {
        String proxyUrl = null;
        for (String name : PROXY_VARS) {
            proxyUrl = envLookup.apply(name);
            if (proxyUrl != null && !proxyUrl.isEmpty()) {
                break;
            }
        }
        if (proxyUrl == null || proxyUrl.isEmpty()) {
            logger.info("Empty proxy url.");
            return null;
        }
        try {
            logger.info("Setup proxy");
            URI uri = new URI(proxyUrl);
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            logger.infof("Use proxy %s.", uri.getHost());
            return new HttpHost(uri.getScheme(), uri.getHost(), port);
        } catch (URISyntaxException e) {
            logger.warnf("Invalid proxy URL '%s': %s", proxyUrl, e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the NO_PROXY exclusion list from environment variables.
     *
     * @return list of lowercase hostname patterns to bypass the proxy for
     */
    static List<String> resolveNoProxy() {
        return resolveNoProxy(System::getenv);
    }

    /**
     * Resolves the NO_PROXY exclusion list using the provided environment variable lookup function.
     * Checks NO_PROXY and no_proxy in order.
     *
     * @param envLookup function to look up environment variable values by name
     * @return list of lowercase hostname patterns to bypass the proxy for
     */
    static List<String> resolveNoProxy(Function<String, String> envLookup) {
        String noProxy = null;
        for (String name : NO_PROXY_VARS) {
            noProxy = envLookup.apply(name);
            if (noProxy != null && !noProxy.isEmpty()) {
                break;
            }
        }
        if (noProxy == null || noProxy.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> patterns = new ArrayList<>();
        for (String entry : noProxy.split(",")) {
            String trimmed = entry.trim();
            if (!trimmed.isEmpty()) {
                patterns.add(trimmed.toLowerCase(Locale.ROOT));
            }
        }
        return patterns;
    }

    /**
     * Checks whether the given hostname should bypass the proxy based on NO_PROXY patterns.
     * <p>
     * Matching rules:
     * <ul>
     *   <li>{@code *} matches all hosts</li>
     *   <li>{@code .example.com} matches {@code example.com} and {@code sub.example.com}</li>
     *   <li>{@code example.com} matches {@code example.com} and {@code sub.example.com}</li>
     * </ul>
     * Matching is case-insensitive.
     *
     * @param hostname        the target hostname
     * @param noProxyPatterns lowercase patterns from NO_PROXY
     * @return true if the proxy should be bypassed for this host
     */
    static boolean isNoProxyHost(String hostname, List<String> noProxyPatterns) {
        if (noProxyPatterns.isEmpty()) {
            return false;
        }
        String host = hostname.toLowerCase(Locale.ROOT);
        for (String pattern : noProxyPatterns) {
            if ("*".equals(pattern)) {
                return true;
            }
            if (pattern.startsWith(".")) {
                String domain = pattern.substring(1);
                if (host.equals(domain) || host.endsWith(pattern)) {
                    return true;
                }
            } else {
                if (host.equals(pattern) || host.endsWith("." + pattern)) {
                    return true;
                }
            }
        }
        return false;
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

    /**
     * Route planner that bypasses the proxy for hosts matching the NO_PROXY patterns.
     */
    private static class NoProxyAwareRoutePlanner extends DefaultProxyRoutePlanner {

        private final List<String> noProxyPatterns;

        NoProxyAwareRoutePlanner(HttpHost proxy, List<String> noProxyPatterns) {
            super(proxy);
            this.noProxyPatterns = noProxyPatterns;
        }

        @Override
        protected HttpHost determineProxy(HttpHost target, HttpContext context) throws HttpException {
            if (isNoProxyHost(target.getHostName(), noProxyPatterns)) {
                logger.debugf("Bypassing proxy for host: %s (matched NO_PROXY)", target.getHostName());
                return null;
            }
            return super.determineProxy(target, context);
        }
    }
}
