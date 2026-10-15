package io.github.adorsysgis.keycloakstatuslist.validation;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.client.ApacheHttpStatusListClient;
import java.util.List;
import nl.altindag.log.LogCaptor;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.JWK;

/**
 * Validation check for scan finding 5: {@code ApacheHttpStatusListClient.registerIssuer()} logs
 * {@code response.getHeaders().toString()} — a JVM array identity like
 * {@code [Lorg.apache.hc.core5.http.Header;@1a2b3c} — which makes the response-header debug log
 * useless for troubleshooting.
 *
 * <p>Fixed contract asserted here: the debug log must render the actual header contents (e.g. via
 * {@code Arrays.toString(response.getHeaders())}). FAILS while the log contains array identity.
 */
@SuppressWarnings("unchecked")
class Finding05ResponseHeaderLogCheck {

    private final LogCaptor logCaptor = LogCaptor.forName("io.github.adorsysgis.keycloakstatuslist");

    @Test
    void registerIssuerShouldLogActualResponseHeaderContents() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        when(httpClient.execute(any(HttpPost.class), any(HttpClientResponseHandler.class)))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
                    when(response.getCode()).thenReturn(201);
                    when(response.getHeaders()).thenReturn(new Header[] {new BasicHeader("X-Trace-Id", "abc-123")});
                    when(response.getEntity()).thenReturn(new StringEntity("{}"));
                    return handler.handleResponse(response);
                });

        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, null);
        client.registerIssuer("issuer-1", mock(JWK.class));

        List<String> debugLogs = logCaptor.getDebugLogs();
        assertTrue(
                debugLogs.stream().noneMatch(line -> line.contains("[Lorg.apache.hc.core5.http.Header;@")),
                "The response-header debug log contains a JVM array identity ([Lorg.apache.hc.core5.http.Header;@...). "
                        + "Log the actual header contents instead, e.g. Arrays.toString(response.getHeaders()). "
                        + "Matching debug logs: "
                        + debugLogs.stream()
                                .filter(line -> line.contains("[Lorg.apache.hc.core5.http.Header;@"))
                                .toList());
        assertTrue(
                debugLogs.stream().anyMatch(line -> line.contains("X-Trace-Id")),
                "The registerIssuer debug log should include the actual response header contents "
                        + "(e.g. 'X-Trace-Id: abc-123') so the log is useful when troubleshooting "
                        + "credential-issuer registration. Debug logs captured: "
                        + debugLogs);
    }
}
