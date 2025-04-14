package com.adorsys.keycloakstatuslist;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider; 
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.events.TokenStatusEventListenerProvider;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.StatusListService;

public class TokenStatusPluginTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private RealmModel realm;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm(anyString())).thenReturn(realm);
        when(realm.getName()).thenReturn("test-realm");
    }

    @Test
    public void testTokenStatusModel() {
        TokenStatus activeToken = new TokenStatus();
        activeToken.setTokenId("token-123");
        activeToken.setUserId("user-456");
        activeToken.setStatus("ACTIVE");
        activeToken.setClientId("client-789");
        activeToken.setIssuer("test-realm");
        activeToken.setIssuedAt(Instant.now());
        Instant expiresAt = Instant.now().plusSeconds(3600);
        activeToken.setExpiresAt(expiresAt);

        assertEquals("token-123", activeToken.getTokenId());
        assertEquals("user-456", activeToken.getUserId());
        assertEquals("ACTIVE", activeToken.getStatus());
        assertEquals("client-789", activeToken.getClientId());
        assertEquals("test-realm", activeToken.getIssuer());
        assertEquals(expiresAt, activeToken.getExpiresAt());
        assertNull(activeToken.getRevokedAt());

        TokenStatus revokedToken = new TokenStatus();
        revokedToken.setTokenId("token-123");
        revokedToken.setStatus("REVOKED");
        Instant revokedAt = Instant.now();
        revokedToken.setRevokedAt(revokedAt);

        assertEquals("REVOKED", revokedToken.getStatus());
        assertEquals(revokedAt, revokedToken.getRevokedAt());
    }

    @Test
    public void testStatusListConfigLoading() {
        when(realm.getAttribute(eq("status-list-enabled"))).thenReturn("true");
        when(realm.getAttribute(eq("status-list-server-url"))).thenReturn("https://test-server.com/api");
        when(realm.getAttribute(eq("status-list-auth-token"))).thenReturn("secret-token");
        when(realm.getAttribute(eq("status-list-connect-timeout"))).thenReturn("2000");
        when(realm.getAttribute(eq("status-list-read-timeout"))).thenReturn("3000");
        when(realm.getAttribute(eq("status-list-retry-count"))).thenReturn("5");

        StatusListConfig config = new StatusListConfig(session, realm);

        assertTrue(config.isEnabled());
        assertEquals("https://test-server.com/api", config.getServerUrl());
        assertEquals("secret-token", config.getAuthToken());
        assertEquals(2000, config.getConnectTimeout());
        assertEquals(3000, config.getReadTimeout());
        assertEquals(5, config.getRetryCount());
    }

    @Test
    public void testStatusListConfigDefaults() {
        when(realm.getAttribute(anyString())).thenReturn(null);

        StatusListConfig config = new StatusListConfig(session, realm);

        assertFalse(config.isEnabled());
        assertEquals("http://localhost:8090/api/v1/token-status", config.getServerUrl());
        assertEquals("", config.getAuthToken());
        assertEquals(5000, config.getConnectTimeout());
        assertEquals(5000, config.getReadTimeout());
        assertEquals(3, config.getRetryCount());
    }

    @Test
    public void testStatusListServicePublish() throws Exception {
        StatusListConfig mockConfig = mock(StatusListConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);
        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com/api");
        when(mockConfig.getAuthToken()).thenReturn("secret-token");
        when(mockConfig.getConnectTimeout()).thenReturn(5000);
        when(mockConfig.getReadTimeout()).thenReturn(5000);
        when(mockConfig.getRetryCount()).thenReturn(3);

        TokenStatus tokenStatus = new TokenStatus();
        tokenStatus.setTokenId("token-123");
        tokenStatus.setStatus("ACTIVE");

        when(httpResponse.getCode()).thenReturn(200);
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);

        try (var httpClients = mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {
            var mockBuilder = mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);
            httpClients.when(HttpClients::custom).thenReturn(mockBuilder);

            StatusListService service = new StatusListService(mockConfig);
            boolean result = service.publishTokenStatus(tokenStatus);

            assertTrue(result);

            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
            verify(httpClient).execute(requestCaptor.capture());

            HttpPost capturedRequest = requestCaptor.getValue();
            assertEquals("https://test-server.com/api", capturedRequest.getUri().toString());
        }
    }

    @Test
    public void testStatusListServiceUpdate() throws Exception {
        StatusListConfig mockConfig = mock(StatusListConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);
        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com/api");
        when(mockConfig.getAuthToken()).thenReturn("secret-token");
        when(mockConfig.getConnectTimeout()).thenReturn(5000);
        when(mockConfig.getReadTimeout()).thenReturn(5000);
        when(mockConfig.getRetryCount()).thenReturn(3);

        TokenStatus tokenStatus = new TokenStatus();
        tokenStatus.setTokenId("token-123");
        tokenStatus.setStatus("REVOKED");
        tokenStatus.setRevokedAt(Instant.now());

        CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        when(httpResponse.getCode()).thenReturn(200);
        when(httpClient.execute(any(HttpPut.class))).thenReturn(httpResponse);

        try (var httpClients = mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {
            var mockBuilder = mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);
            httpClients.when(HttpClients::custom).thenReturn(mockBuilder);

            StatusListService service = new StatusListService(mockConfig);
            boolean result = service.updateTokenStatus(tokenStatus);

            assertTrue(result, "Update should succeed with mocked 200 response");

            ArgumentCaptor<HttpPut> requestCaptor = ArgumentCaptor.forClass(HttpPut.class);
            verify(httpClient).execute(requestCaptor.capture());

            HttpPut capturedRequest = requestCaptor.getValue();
            assertEquals("https://test-server.com/api/token-123", capturedRequest.getUri().toString());
            assertTrue(capturedRequest.getHeader("Authorization").getValue().contains("secret-token"));
            assertEquals("application/json", capturedRequest.getHeader("Content-Type").getValue());
        }
    }

    @Test
    public void testStatusListServiceRetry() throws Exception {
        StatusListConfig mockConfig = mock(StatusListConfig.class);
        when(mockConfig.isEnabled()).thenReturn(true);
        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com/api");
        when(mockConfig.getAuthToken()).thenReturn("secret-token");
        when(mockConfig.getConnectTimeout()).thenReturn(5000);
        when(mockConfig.getReadTimeout()).thenReturn(5000);
        when(mockConfig.getRetryCount()).thenReturn(2);

        TokenStatus tokenStatus = new TokenStatus();
        tokenStatus.setTokenId("token-123");
        tokenStatus.setStatus("ACTIVE");

        CloseableHttpResponse errorResponse = mock(CloseableHttpResponse.class);
        when(errorResponse.getCode()).thenReturn(500);

        CloseableHttpResponse successResponse = mock(CloseableHttpResponse.class);
        when(successResponse.getCode()).thenReturn(200);

        when(httpClient.execute(any(HttpPost.class)))
                .thenReturn(errorResponse)
                .thenReturn(successResponse);

        try (var httpClients = mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {
            var mockBuilder = mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);
            httpClients.when(HttpClients::custom).thenReturn(mockBuilder);

            StatusListService service = new StatusListService(mockConfig);
            boolean result = service.publishTokenStatus(tokenStatus);

            assertTrue(result);
            verify(httpClient, times(2)).execute(any(HttpPost.class));
        }
    }

    @Test
    public void testEventListenerForLoginEvent() {
        Event loginEvent = new Event();
        loginEvent.setType(EventType.LOGIN);
        loginEvent.setRealmId("test-realm");
        loginEvent.setClientId("test-client");
        loginEvent.setUserId("test-user");

        Map<String, String> details = new HashMap<>();
        details.put("token_id", "test-token-id");
        details.put("exp", String.valueOf(System.currentTimeMillis() / 1000 + 3600));
        loginEvent.setDetails(details);

        StatusListConfig config = mock(StatusListConfig.class);
        when(config.isEnabled()).thenReturn(false); // Prevent actual HTTP calls
        TokenStatusEventListenerProvider listener = new TokenStatusEventListenerProvider(session);
        listener.onEvent(loginEvent);
        verify(realmProvider).getRealm("test-realm");
    }

    @Test
    public void testEventListenerForLogoutEvent() {
        Event logoutEvent = new Event();
        logoutEvent.setType(EventType.LOGOUT);
        logoutEvent.setRealmId("test-realm");
        logoutEvent.setClientId("test-client");
        logoutEvent.setUserId("test-user");

        Map<String, String> details = new HashMap<>();
        details.put("token_id", "test-token-id");
        logoutEvent.setDetails(details);

        StatusListConfig config = mock(StatusListConfig.class);
        when(config.isEnabled()).thenReturn(false); // Prevent actual HTTP calls
        TokenStatusEventListenerProvider listener = new TokenStatusEventListenerProvider(session);
        listener.onEvent(logoutEvent);
        verify(realmProvider).getRealm("test-realm");
    }

    @Test
    public void testEventListenerIgnoresIrrelevantEvents() {
        Event updateProfileEvent = new Event();
        updateProfileEvent.setType(EventType.UPDATE_PROFILE);
        updateProfileEvent.setRealmId("test-realm");

        TokenStatusEventListenerProvider listener = new TokenStatusEventListenerProvider(session);
        listener.onEvent(updateProfileEvent);

        verify(realmProvider, never()).getRealm(anyString());
    }

    @Test
    public void testEventListenerIgnoresEventsWithoutTokenId() {
        Event loginEvent = new Event();
        loginEvent.setType(EventType.LOGIN);
        loginEvent.setRealmId("test-realm");
        loginEvent.setClientId("test-client");
        loginEvent.setUserId("test-user");
        loginEvent.setDetails(new HashMap<>());

        TokenStatusEventListenerProvider listener = new TokenStatusEventListenerProvider(session);
        listener.onEvent(loginEvent);

        verify(realmProvider).getRealm("test-realm");
    }

}