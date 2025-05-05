//package com.adorsys.keycloakstatuslist;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//
//import java.io.ByteArrayInputStream;
//import java.io.IOException;
//import java.time.Instant;
//import java.util.HashMap;
//import java.util.Map;
//
//import org.apache.hc.client5.http.classic.methods.HttpPost;
//import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
//import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
//import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
//import org.apache.hc.client5.http.impl.classic.HttpClients;
//import org.apache.hc.core5.http.HttpEntity;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.keycloak.events.Event;
//import org.keycloak.events.EventType;
//import org.keycloak.models.KeycloakContext;
//import org.keycloak.models.KeycloakSession;
//import org.keycloak.models.RealmModel;
//import org.keycloak.models.RealmProvider;
//import org.mockito.ArgumentCaptor;
//import org.mockito.Mock;
//import org.mockito.MockedStatic;
//import org.mockito.junit.jupiter.MockitoExtension;
//
//import com.adorsys.keycloakstatuslist.config.StatusListConfig;
//import com.adorsys.keycloakstatuslist.events.SdJwtStatusEventListenerProvider;
//import com.adorsys.keycloakstatuslist.exception.StatusListException;
//import com.adorsys.keycloakstatuslist.model.TokenStatus;
//import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
//import com.adorsys.keycloakstatuslist.service.StatusListService;
//
//@ExtendWith(MockitoExtension.class)
//public class TokenStatusPluginTest {
//
//    @Mock
//    private KeycloakSession session;
//
//    @Mock
//    private KeycloakContext context;
//
//    @Mock
//    private CloseableHttpClient httpClient;
//
//    @Mock
//    private CloseableHttpResponse httpResponse;
//
//    @Mock
//    private HttpEntity httpEntity;
//
//    @Mock
//    private RealmProvider realmProvider;
//
//    @Mock
//    private RealmModel realm;
//
//    @BeforeEach
//    public void setup() throws IOException {
//        when(session.getContext()).thenReturn(context);
//        when(context.getRealm()).thenReturn(realm);
//        when(session.realms()).thenReturn(realmProvider);
//        when(realmProvider.getRealm(anyString())).thenReturn(realm);
//        when(realm.getName()).thenReturn("test-realm");
//
//        // Setup for HTTP responses
//        when(httpResponse.getEntity()).thenReturn(httpEntity);
//        when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream("{}".getBytes()));
//    }
//
//    @Test
//    public void testTokenStatusRecordModel() {
//        TokenStatusRecord record = new TokenStatusRecord();
//        record.setCredentialId("cred-123");
//        record.setIssuerId("test-realm");
//        record.setStatus(TokenStatus.ACTIVE);
//        record.setCredentialType("VerifiableCredential");
//        record.setIssuedAt(Instant.now());
//        Instant expiresAt = Instant.now().plusSeconds(3600);
//        record.setExpiresAt(expiresAt);
//
//        assertEquals("cred-123", record.getCredentialId());
//        assertEquals("test-realm", record.getIssuerId());
//        assertEquals(TokenStatus.ACTIVE, record.getStatus());
//        assertEquals("VerifiableCredential", record.getCredentialType());
//        assertEquals(expiresAt, record.getExpiresAt());
//        assertNull(record.getRevokedAt());
//
//        TokenStatusRecord revokedRecord = new TokenStatusRecord();
//        revokedRecord.setCredentialId("cred-123");
//        revokedRecord.setStatus(TokenStatus.REVOKED);
//        Instant revokedAt = Instant.now();
//        revokedRecord.setRevokedAt(revokedAt);
//
//        assertEquals(TokenStatus.REVOKED, revokedRecord.getStatus());
//        assertEquals(revokedAt, revokedRecord.getRevokedAt());
//    }
//
//    @Test
//    public void testStatusListConfigLoading() {
//        when(realm.getAttribute(eq("status-list-enabled"))).thenReturn("true");
//        when(realm.getAttribute(eq("status-list-server-url"))).thenReturn("https://statuslist.eudi-adorsys.com/");
//        when(realm.getAttribute(eq("status-list-auth-token"))).thenReturn("secret-token");
//        when(realm.getAttribute(eq("status-list-connect-timeout"))).thenReturn("2000");
//        when(realm.getAttribute(eq("status-list-read-timeout"))).thenReturn("3000");
//        when(realm.getAttribute(eq("status-list-retry-count"))).thenReturn("5");
//
//        StatusListConfig config = new StatusListConfig(session, realm);
//
//        assertTrue(config.isEnabled());
//        assertEquals("https://statuslist.eudi-adorsys.com/", config.getServerUrl());
//        assertEquals("secret-token", config.getAuthToken());
//        assertEquals(2000, config.getConnectTimeout());
//        assertEquals(3000, config.getReadTimeout());
//        assertEquals(5, config.getRetryCount());
//    }
//
//    @Test
//    public void testStatusListConfigDefaults() {
//        when(realm.getAttribute(anyString())).thenReturn(null);
//
//        StatusListConfig config = new StatusListConfig(session, realm);
//
//        assertFalse(config.isEnabled());
//        assertEquals("https://statuslist.eudi-adorsys.com/", config.getServerUrl());
//        assertEquals("", config.getAuthToken());
//        assertEquals(5000, config.getConnectTimeout());
//        assertEquals(5000, config.getReadTimeout());
//        assertEquals(3, config.getRetryCount());
//    }
//
//    @Test
//    public void testStatusListServiceRegisterCredential() throws Exception {
//        StatusListConfig mockConfig = mock(StatusListConfig.class);
//        when(mockConfig.isEnabled()).thenReturn(true);
//        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com");
//        when(mockConfig.getAuthToken()).thenReturn("secret-token");
//        when(mockConfig.getConnectTimeout()).thenReturn(5000);
//        when(mockConfig.getReadTimeout()).thenReturn(5000);
//        when(mockConfig.getRetryCount()).thenReturn(3);
//
//        TokenStatusRecord record = new TokenStatusRecord();
//        record.setCredentialId("cred-123");
//        record.setIssuerId("test-realm");
//        record.setStatus(TokenStatus.ACTIVE);
//
//        when(httpResponse.getCode()).thenReturn(200);
//        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
//
//        try (MockedStatic<HttpClients> httpClientsMock = mockStatic(HttpClients.class)) {
//            HttpClientBuilder mockBuilder = mock(HttpClientBuilder.class);
//            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
//            when(mockBuilder.build()).thenReturn(httpClient);
//            httpClientsMock.when(HttpClients::custom).thenReturn(mockBuilder);
//
//            StatusListService service = new StatusListService(mockConfig);
//
//            // No exception means success
//            assertDoesNotThrow(() -> service.registerCredential(record));
//
//            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
//            verify(httpClient).execute(requestCaptor.capture());
//
//            HttpPost capturedRequest = requestCaptor.getValue();
//            assertEquals("https://test-server.com/credentials", capturedRequest.getUri().toString());
//            assertEquals("Bearer secret-token", capturedRequest.getFirstHeader("Authorization").getValue());
//            assertEquals("application/json", capturedRequest.getFirstHeader("Content-Type").getValue());
//        }
//    }
//
//    @Test
//    public void testStatusListServiceRevokeCredential() throws Exception {
//        StatusListConfig mockConfig = mock(StatusListConfig.class);
//        when(mockConfig.isEnabled()).thenReturn(true);
//        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com");
//        when(mockConfig.getAuthToken()).thenReturn("secret-token");
//        when(mockConfig.getConnectTimeout()).thenReturn(5000);
//        when(mockConfig.getReadTimeout()).thenReturn(5000);
//        when(mockConfig.getRetryCount()).thenReturn(3);
//
//        TokenStatusRecord record = new TokenStatusRecord();
//        record.setCredentialId("cred-123");
//        record.setStatus(TokenStatus.REVOKED);
//        record.setRevokedAt(Instant.now());
//
//        when(httpResponse.getCode()).thenReturn(200);
//        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
//
//        try (MockedStatic<HttpClients> httpClientsMock = mockStatic(HttpClients.class)) {
//            HttpClientBuilder mockBuilder = mock(HttpClientBuilder.class);
//            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
//            when(mockBuilder.build()).thenReturn(httpClient);
//            httpClientsMock.when(HttpClients::custom).thenReturn(mockBuilder);
//
//            StatusListService service = new StatusListService(mockConfig);
//
//            // No exception means success
//            assertDoesNotThrow(() -> service.revokeCredential(record));
//
//            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
//            verify(httpClient).execute(requestCaptor.capture());
//
//            HttpPost capturedRequest = requestCaptor.getValue();
//            assertEquals("https://test-server.com/credentials/cred-123/revoke",
//                    capturedRequest.getUri().toString());
//        }
//    }
//
//    @Test
//    public void testStatusListServiceRetry() throws Exception {
//        StatusListConfig mockConfig = mock(StatusListConfig.class);
//        when(mockConfig.isEnabled()).thenReturn(true);
//        when(mockConfig.getServerUrl()).thenReturn("https://test-server.com");
//        when(mockConfig.getAuthToken()).thenReturn("secret-token");
//        when(mockConfig.getConnectTimeout()).thenReturn(5000);
//        when(mockConfig.getReadTimeout()).thenReturn(5000);
//        when(mockConfig.getRetryCount()).thenReturn(2);
//
//        TokenStatusRecord record = new TokenStatusRecord();
//        record.setCredentialId("cred-123");
//        record.setStatus(TokenStatus.ACTIVE);
//
//        CloseableHttpResponse errorResponse = mock(CloseableHttpResponse.class);
//        when(errorResponse.getCode()).thenReturn(500);
//        when(errorResponse.getEntity()).thenReturn(httpEntity);
//
//        when(httpClient.execute(any(HttpPost.class)))
//                .thenReturn(errorResponse)
//                .thenReturn(httpResponse);  // Second call succeeds with 200 OK
//
//        try (MockedStatic<HttpClients> httpClientsMock = mockStatic(HttpClients.class)) {
//            HttpClientBuilder mockBuilder = mock(HttpClientBuilder.class);
//            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
//            when(mockBuilder.build()).thenReturn(httpClient);
//            httpClientsMock.when(HttpClients::custom).thenReturn(mockBuilder);
//
//            StatusListService service = new StatusListService(mockConfig);
//
//            // No exception means success (due to the retry mechanism)
//            assertDoesNotThrow(() -> service.registerCredential(record));
//
//            // Verify that the client executed twice (first failure, then success)
//            verify(httpClient, times(2)).execute(any(HttpPost.class));
//        }
//    }
//
//    @Test
//    public void testEventListenerForSDJWTEvents() {
//        Event jwtEvent = new Event();
//        jwtEvent.setType(EventType.CUSTOM_REQUIRED_ACTION); // Using a standard event type as a placeholder
//        jwtEvent.setRealmId("test-realm");
//        jwtEvent.setClientId("test-client");
//        jwtEvent.setUserId("test-user");
//        // Setting the actual type via reflection since we can't create custom EventType directly
//        try {
//            var field = jwtEvent.getClass().getDeclaredField("type");
//            field.setAccessible(true);
//            field.set(jwtEvent, "sd_jwt_issued"); // Using string as this is how it's checked in implementation
//        } catch (Exception e) {
//            fail("Failed to set custom event type");
//        }
//
//        Map<String, String> details = new HashMap<>();
//        details.put("credential_id", "test-cred-id");
//        details.put("expires_at", String.valueOf(System.currentTimeMillis() / 1000 + 3600));
//        jwtEvent.setDetails(details);
//
//        // Create listener with mocked dependencies to prevent actual HTTP calls
//        SdJwtStatusEventListenerProvider listener = new SdJwtStatusEventListenerProvider(session);
//        listener.onEvent(jwtEvent);
//
//        // Verify realm was looked up
//        verify(realmProvider).getRealm("test-realm");
//    }
//
//    @Test
//    public void testEventListenerIgnoresEventsWithoutCredentialId() {
//        Event jwtEvent = new Event();
//        try {
//            var field = jwtEvent.getClass().getDeclaredField("type");
//            field.setAccessible(true);
//            field.set(jwtEvent, "sd_jwt_issued");
//        } catch (Exception e) {
//            fail("Failed to set custom event type");
//        }
//        jwtEvent.setRealmId("test-realm");
//        jwtEvent.setDetails(new HashMap<>());  // No credential_id
//
//        SdJwtStatusEventListenerProvider listener = new SdJwtStatusEventListenerProvider(session);
//        listener.onEvent(jwtEvent);
//
//        // It should get the realm but since there's no credential_id, no further processing
//        verify(realmProvider).getRealm("test-realm");
//    }
//
//    @Test
//    public void testDisabledServiceThrowsException() {
//        StatusListConfig mockConfig = mock(StatusListConfig.class);
//        when(mockConfig.isEnabled()).thenReturn(false);
//
//        TokenStatusRecord record = new TokenStatusRecord();
//        record.setCredentialId("cred-123");
//
//        StatusListService service = new StatusListService(mockConfig);
//
//        assertThrows(StatusListException.class, () -> service.registerCredential(record));
//        assertThrows(StatusListException.class, () -> service.revokeCredential(record));
//        assertThrows(StatusListException.class, () -> service.checkCredentialStatus("cred-123"));
//    }
//}