package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
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

    public static final int DEFAULT_CONNECT_TIMEOUT = 30000;

    /**
     * Creates an HTTP client for issuance operations (runtime/foreground).
     * Typically has a shorter timeout and fewer/no retries to protect tail latency.
     *
     * @param config the status list configuration
     * @return configured HTTP client
     */
    public static CloseableHttpClient getIssuanceHttpClient(StatusListConfig config) {
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

        HttpHost proxy = resolveProxy();
        if (proxy != null) {
            builder.setProxy(proxy);
            logger.infof("Using HTTP proxy: %s", proxy);
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
        String[] candidates = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"};
        String proxyUrl = null;
        for (String name : candidates) {
            proxyUrl = envLookup.apply(name);
            if (proxyUrl != null && !proxyUrl.isEmpty()) {
                break;
            }
        }
        if (proxyUrl == null || proxyUrl.isEmpty()) {
            return null;
        }
        try {
            URI uri = new URI(proxyUrl);
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return new HttpHost(uri.getScheme(), uri.getHost(), port);
        } catch (URISyntaxException e) {
            logger.warnf("Invalid proxy URL '%s': %s", proxyUrl, e.getMessage());
            return null;
        }
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
