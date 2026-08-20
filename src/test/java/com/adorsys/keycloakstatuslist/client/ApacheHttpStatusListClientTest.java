package com.adorsys.keycloakstatuslist.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.CircuitBreaker;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.UUID;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.JWK;
import org.mockito.ArgumentCaptor;

@SuppressWarnings("unchecked")
class ApacheHttpStatusListClientTest {

    @Test
    void registerIssuerShouldSucceedOn2xx() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        mockPostResponse(httpClient, 201, "{\"ok\":true}");
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, null);

        client.registerIssuer("issuer-1", mock(JWK.class));

        ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
        verify(httpClient).execute(requestCaptor.capture(), any(HttpClientResponseHandler.class));
        assertEquals(
                "https://status.example.com/api/v1/credentials",
                requestCaptor.getValue().getUri().toString());
    }

    @Test
    void registerIssuerShouldAcceptConflictAsAlreadyRegistered() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        mockPostResponse(httpClient, 409, "{\"message\":\"already exists\"}");
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, null);

        client.registerIssuer("issuer-1", mock(JWK.class));

        ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
        verify(httpClient).execute(requestCaptor.capture(), any(HttpClientResponseHandler.class));
        assertEquals(
                "https://status.example.com/api/v1/credentials",
                requestCaptor.getValue().getUri().toString());
    }

    @Test
    void checkStatusListExistsShouldHandle200And404() throws Exception {
        CloseableHttpClient okClient = mock(CloseableHttpClient.class);
        mockGetResponse(okClient, 200, "");
        ApacheHttpStatusListClient ok =
                new ApacheHttpStatusListClient("https://status.example.com/", "token", okClient, null);
        assertTrue(ok.checkStatusListExists("list-1"));
        ArgumentCaptor<HttpGet> okRequestCaptor = ArgumentCaptor.forClass(HttpGet.class);
        verify(okClient).execute(okRequestCaptor.capture(), any(HttpClientResponseHandler.class));
        assertEquals(
                "https://status.example.com/api/v1/status-lists/list-1",
                okRequestCaptor.getValue().getUri().toString());
        assertEquals(
                "application/statuslist+jwt",
                okRequestCaptor.getValue().getFirstHeader("Accept").getValue());

        CloseableHttpClient notFoundClient = mock(CloseableHttpClient.class);
        mockGetResponse(notFoundClient, 404, "");
        ApacheHttpStatusListClient notFound =
                new ApacheHttpStatusListClient("https://status.example.com/", "token", notFoundClient, null);
        assertFalse(notFound.checkStatusListExists("list-2"));
    }

    @Test
    void checkStatusListExistsShouldThrowOnServerError() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        mockGetResponse(httpClient, 500, "{\"error\":\"boom\"}");
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, null);

        assertThrows(StatusListServerException.class, () -> client.checkStatusListExists("list-1"));
    }

    @Test
    void publishAndUpdateShouldUseExpectedEndpoints() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        mockPutResponse(httpClient, 201, "{\"ok\":true}");
        mockPatchResponse(httpClient, 200, "{\"ok\":true}");
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, null);
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-1", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.VALID)));
        StatusListService.StatusListPayload revocationPayload = new StatusListService.StatusListPayload(
                "list-1", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.INVALID)));

        client.publishStatusList(payload, "req-1");
        client.updateStatusList(revocationPayload, "req-2");

        ArgumentCaptor<HttpPut> putCaptor = ArgumentCaptor.forClass(HttpPut.class);
        ArgumentCaptor<HttpPatch> patchCaptor = ArgumentCaptor.forClass(HttpPatch.class);
        verify(httpClient).execute(putCaptor.capture(), any(HttpClientResponseHandler.class));
        verify(httpClient).execute(patchCaptor.capture(), any(HttpClientResponseHandler.class));

        assertEquals(
                "https://status.example.com/api/v1/status-lists/list-1/statuses",
                putCaptor.getValue().getUri().toString());
        assertEquals(
                "https://status.example.com/api/v1/status-lists/list-1/statuses",
                patchCaptor.getValue().getUri().toString());

        String publishBody = EntityUtils.toString(putCaptor.getValue().getEntity());
        String updateBody = EntityUtils.toString(patchCaptor.getValue().getEntity());
        assertTrue(publishBody.contains("\"statuses\""));
        assertTrue(updateBody.contains("\"statuses\""));
        assertTrue(publishBody.contains("\"status\":0"));
        assertTrue(updateBody.contains("\"status\":1"));
        assertFalse(publishBody.contains("\"list_id\""));
        assertFalse(updateBody.contains("\"list_id\""));
        assertFalse(publishBody.contains("\"VALID\""));
        assertFalse(updateBody.contains("\"INVALID\""));
    }

    @Test
    void publishConflictShouldNotCountAsCircuitBreakerFailure() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        mockPutResponse(httpClient, 409, "{\"error\":\"status_list_already_exists\"}");
        CircuitBreaker breaker = createBreaker("client-cb-conflict-" + UUID.randomUUID(), 1, 60, 30);
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, breaker);
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                "list-1", List.of(new StatusListService.StatusListPayload.StatusEntry(1, TokenStatus.VALID)));

        StatusListServerException exception =
                assertThrows(StatusListServerException.class, () -> client.publishStatusList(payload, "req-1"));

        assertEquals(409, exception.getStatusCode());
        assertEquals(0, breaker.getFailureCount());
        assertEquals("CLOSED", breaker.getState());
    }

    @Test
    void checkServerHealthShouldReturnTrueOn2xxAndFalseOnErrors() throws Exception {
        CloseableHttpClient healthyClient = mock(CloseableHttpClient.class);
        mockGetResponse(healthyClient, 200, "");
        ApacheHttpStatusListClient healthy =
                new ApacheHttpStatusListClient("https://status.example.com", "token", healthyClient, null);
        assertTrue(healthy.checkServerHealth());

        CloseableHttpClient unhealthyClient = mock(CloseableHttpClient.class);
        mockGetResponse(unhealthyClient, 503, "");
        ApacheHttpStatusListClient unhealthy =
                new ApacheHttpStatusListClient("https://status.example.com", "token", unhealthyClient, null);
        assertFalse(unhealthy.checkServerHealth());

        CloseableHttpClient ioFailingClient = mock(CloseableHttpClient.class);
        when(ioFailingClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class)))
                .thenThrow(new IOException("down"));
        ApacheHttpStatusListClient ioFailing =
                new ApacheHttpStatusListClient("https://status.example.com", "token", ioFailingClient, null);
        assertFalse(ioFailing.checkServerHealth());
    }

    @Test
    void shouldFailFastWhenCircuitBreakerOpen() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        CircuitBreaker breaker = createBreaker("client-cb-open", 1, 60, 30);
        breaker.recordFailure();
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, breaker);

        assertThrows(StatusListException.class, () -> client.checkStatusListExists("list-1"));
        verify(httpClient, never()).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void shouldWrapInterruptedIOExceptionAsStatusListExceptionAndReInterrupt() throws Exception {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        when(httpClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class)))
                .thenThrow(new InterruptedIOException("timeout"));
        CircuitBreaker breaker = createBreaker("client-cb-timeout", 5, 60, 30);
        ApacheHttpStatusListClient client =
                new ApacheHttpStatusListClient("https://status.example.com", "token", httpClient, breaker);

        assertThrows(StatusListException.class, () -> client.checkStatusListExists("list-1"));
        assertTrue(Thread.currentThread().isInterrupted());
        assertEquals(1, breaker.getFailureCount());
        Thread.interrupted();
    }

    @Test
    void shouldNormalizeServerUrlWithTrailingSlash() {
        ApacheHttpStatusListClient client = new ApacheHttpStatusListClient(
                "https://status.example.com", null, mock(CloseableHttpClient.class), null);

        assertEquals("https://status.example.com/", client.getServerUrl());
    }

    private void mockGetResponse(CloseableHttpClient httpClient, int statusCode, String body) throws Exception {
        when(httpClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class)))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    var response = mock(org.apache.hc.client5.http.impl.classic.CloseableHttpResponse.class);
                    when(response.getCode()).thenReturn(statusCode);
                    when(response.getHeaders()).thenReturn(new Header[0]);
                    when(response.getEntity()).thenReturn(new StringEntity(body));
                    return handler.handleResponse(response);
                });
    }

    private void mockPostResponse(CloseableHttpClient httpClient, int statusCode, String body) throws Exception {
        when(httpClient.execute(any(HttpPost.class), any(HttpClientResponseHandler.class)))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    var response = mock(org.apache.hc.client5.http.impl.classic.CloseableHttpResponse.class);
                    when(response.getCode()).thenReturn(statusCode);
                    when(response.getHeaders()).thenReturn(new Header[0]);
                    when(response.getEntity()).thenReturn(new StringEntity(body));
                    return handler.handleResponse(response);
                });
    }

    private void mockPutResponse(CloseableHttpClient httpClient, int statusCode, String body) throws Exception {
        when(httpClient.execute(any(HttpPut.class), any(HttpClientResponseHandler.class)))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    var response = mock(org.apache.hc.client5.http.impl.classic.CloseableHttpResponse.class);
                    when(response.getCode()).thenReturn(statusCode);
                    when(response.getHeaders()).thenReturn(new Header[0]);
                    when(response.getEntity()).thenReturn(new StringEntity(body));
                    return handler.handleResponse(response);
                });
    }

    private void mockPatchResponse(CloseableHttpClient httpClient, int statusCode, String body) throws Exception {
        when(httpClient.execute(any(HttpPatch.class), any(HttpClientResponseHandler.class)))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    var response = mock(org.apache.hc.client5.http.impl.classic.CloseableHttpResponse.class);
                    when(response.getCode()).thenReturn(statusCode);
                    when(response.getHeaders()).thenReturn(new Header[0]);
                    when(response.getEntity()).thenReturn(new StringEntity(body));
                    return handler.handleResponse(response);
                });
    }

    private CircuitBreaker createBreaker(String name, int failureThreshold, int windowSeconds, int cooldownSeconds)
            throws ReflectiveOperationException {
        Method method =
                CircuitBreaker.class.getDeclaredMethod("getInstance", String.class, int.class, int.class, int.class);
        method.setAccessible(true);
        return (CircuitBreaker) method.invoke(null, name, failureThreshold, windowSeconds, cooldownSeconds);
    }
}
