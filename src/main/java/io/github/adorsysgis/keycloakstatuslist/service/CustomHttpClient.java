package io.github.adorsysgis.keycloakstatuslist.service;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jboss.logging.Logger;
import org.keycloak.utils.StringUtil;

public class CustomHttpClient {

    private static final Logger logger = Logger.getLogger(CustomHttpClient.class);

    /**
     * Proxy environment variables in order of precedence. Each name is looked up case-insensitively,
     * so the lowercase spellings (e.g. {@code https_proxy}) are covered as well.
     */
    private static final String[] PROXY_ENV_VARS = {"HTTPS_PROXY", "HTTP_PROXY"};

    /**
     * Environment variable holding the proxy exclusion list. Looked up case-insensitively.
     */
    private static final String NO_PROXY_ENV_VAR = "NO_PROXY";

    private static final String NO_PROXY_SEPARATOR = ",";
    private static final String NO_PROXY_WILDCARD = "*";
    private static final String DOMAIN_SEPARATOR = ".";

    private static final int DEFAULT_HTTP_PROXY_PORT = 80;
    private static final int DEFAULT_HTTPS_PROXY_PORT = 443;

    private static final String CA_CERTIFICATE_TYPE = "X.509";
    private static final String CA_TRUST_STORE_ALIAS = "status-list-ca";

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

        // Support usage of an HTTP proxy - reuses the standard Keycloak proxy/no-proxy env vars
        HttpHost proxy = resolveProxy();
        if (proxy != null) {
            List<String> noProxyPatterns = resolveNoProxy();
            logger.infof("Using HTTP proxy %s, bypassed for %s.", proxy, noProxyPatterns);
            if (noProxyPatterns.isEmpty()) {
                builder.setProxy(proxy);
            } else {
                builder.setRoutePlanner(new NoProxyAwareRoutePlanner(proxy, noProxyPatterns));
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
                logger.warn("TLS trust-all is enabled - all server certificates will be accepted.");
                return SSLContextBuilder.create()
                        .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                        .build();
            }

            String caCertPath = config.getTlsCaCertPath();
            if (StringUtil.isNotBlank(caCertPath)) {
                logger.infof("Loading custom CA certificate from %s.", caCertPath);
                return buildSslContextFromCaCert(caCertPath);
            }
        } catch (GeneralSecurityException | IOException e) {
            logger.errorf(e, "Failed to build custom SSLContext, falling back to JVM defaults.");
        }
        return null;
    }

    /**
     * Builds an SSLContext that trusts a specific PEM-encoded CA certificate file.
     *
     * @param caCertPath path to the PEM-encoded CA certificate
     * @return configured SSLContext
     * @throws GeneralSecurityException if the certificate is invalid or the SSLContext cannot be built
     * @throws IOException if the certificate file cannot be read
     */
    static SSLContext buildSslContextFromCaCert(String caCertPath) throws GeneralSecurityException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CA_CERTIFICATE_TYPE);
        X509Certificate caCert;
        try (FileInputStream fis = new FileInputStream(caCertPath)) {
            caCert = (X509Certificate) certificateFactory.generateCertificate(fis);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry(CA_TRUST_STORE_ALIAS, caCert);

        return SSLContextBuilder.create().loadTrustMaterial(trustStore, null).build();
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
     * HTTPS_PROXY takes precedence over HTTP_PROXY, each resolved case-insensitively.
     *
     * @param envLookup function to look up environment variable values by name
     * @return the proxy HttpHost, or null if no proxy is configured
     */
    static HttpHost resolveProxy(Function<String, String> envLookup) {
        String proxyUrl = null;
        for (String name : PROXY_ENV_VARS) {
            proxyUrl = lookupEnv(envLookup, name);
            if (StringUtil.isNotBlank(proxyUrl)) {
                break;
            }
        }
        if (StringUtil.isBlank(proxyUrl)) {
            return null;
        }
        try {
            URI uri = new URI(proxyUrl.trim());
            if (StringUtil.isBlank(uri.getHost())) {
                logger.warnf("Proxy URL '%s' does not contain a host, ignoring it.", proxyUrl);
                return null;
            }
            int port = uri.getPort();
            if (port < 0) {
                port = URIScheme.HTTPS.getId().equalsIgnoreCase(uri.getScheme())
                        ? DEFAULT_HTTPS_PROXY_PORT
                        : DEFAULT_HTTP_PROXY_PORT;
            }
            return new HttpHost(uri.getScheme(), uri.getHost(), port);
        } catch (URISyntaxException e) {
            logger.warnf("Invalid proxy URL '%s': %s", proxyUrl, e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the NO_PROXY exclusion list from the environment.
     *
     * @return list of lowercase hostname patterns to bypass the proxy for
     */
    static List<String> resolveNoProxy() {
        return resolveNoProxy(System::getenv);
    }

    /**
     * Resolves the NO_PROXY exclusion list using the provided environment variable lookup function.
     * The variable name is resolved case-insensitively.
     *
     * @param envLookup function to look up environment variable values by name
     * @return list of lowercase hostname patterns to bypass the proxy for
     */
    static List<String> resolveNoProxy(Function<String, String> envLookup) {
        String noProxy = lookupEnv(envLookup, NO_PROXY_ENV_VAR);
        if (StringUtil.isBlank(noProxy)) {
            return List.of();
        }
        return Arrays.stream(noProxy.split(NO_PROXY_SEPARATOR))
                .map(String::trim)
                .filter(StringUtil::isNotBlank)
                .map(pattern -> pattern.toLowerCase(Locale.ROOT))
                .toList();
    }

    /**
     * Looks up an environment variable case-insensitively, preferring the given (uppercase) spelling
     * over its lowercase variant.
     *
     * @param envLookup function to look up environment variable values by name
     * @param name      the canonical, uppercase variable name
     * @return the resolved value, or null if neither spelling is set
     */
    private static String lookupEnv(Function<String, String> envLookup, String name) {
        String value = envLookup.apply(name);
        if (StringUtil.isBlank(value)) {
            value = envLookup.apply(name.toLowerCase(Locale.ROOT));
        }
        return value;
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
        String host = hostname.toLowerCase(Locale.ROOT);
        for (String pattern : noProxyPatterns) {
            if (NO_PROXY_WILDCARD.equals(pattern)) {
                return true;
            }
            String domain = pattern.startsWith(DOMAIN_SEPARATOR) ? pattern.substring(1) : pattern;
            if (host.equals(domain) || host.endsWith(DOMAIN_SEPARATOR + domain)) {
                return true;
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
                Boolean isRetriable = status >= HttpStatus.SC_INTERNAL_SERVER_ERROR;
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
                logger.debugf("Bypassing proxy for host %s (matched NO_PROXY).", target.getHostName());
                return null;
            }
            return super.determineProxy(target, context);
        }
    }
}
