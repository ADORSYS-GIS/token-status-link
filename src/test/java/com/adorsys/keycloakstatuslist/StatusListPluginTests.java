package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.client.StatusListClient;
import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.events.TokenStatusEventListenerProvider;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeyManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class StatusListPluginTests {

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private KeycloakContext context;

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private KeyManager keyManager;

    @Mock
    private KeyWrapper keyWrapper;

    @Mock
    private PublicKey publicKey;

    @InjectMocks
    private StatusListClient statusListClient;

    private StatusListService statusListService;

    private TokenStatusEventListenerProvider eventListenerProvider; // Removed @InjectMocks

    private final String serverUrl = "http://localhost:8080/";
    private final String authToken = "test-token";

    @BeforeEach
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        // Mock session and context
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getName()).thenReturn("test-realm");

        // Mock KeyManager
        when(session.keys()).thenReturn(keyManager);
        when(keyManager.getActiveKey(any(RealmModel.class), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(publicKey.toString()).thenReturn("MIIBIjANBgkqhki...");
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        // Initialize StatusListClient with mocked HTTP client
        statusListClient = new StatusListClient(serverUrl, authToken, 1000, 1000);
        Field httpClientField = StatusListClient.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        httpClientField.set(statusListClient, httpClient);

        // Initialize StatusListService with mocked HTTP client
        statusListService = new StatusListService(serverUrl, authToken, 1000, 1000, 3);
        Field httpClientFieldService = StatusListService.class.getDeclaredField("httpClient");
        httpClientFieldService.setAccessible(true);
        java.net.http.HttpClient mockHttpClient = mock(java.net.http.HttpClient.class);
        httpClientFieldService.set(statusListService, mockHttpClient);

        // Initialize event listener after mock setup
        eventListenerProvider = new TokenStatusEventListenerProvider(session);
    }

    @Test
    public void testStatusListClient_PublishTokenStatus_Success() throws IOException {
        // Arrange
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        when(httpResponse.getCode()).thenReturn(HttpStatus.SC_OK);

        // Act
        boolean result = statusListClient.publishTokenStatus("token123", "LOGIN");

        // Assert
        assertTrue(result);
        verify(httpClient, times(1)).execute(any(HttpPost.class));
    }

    @Test
    public void testStatusListClient_PublishTokenStatus_Failure() throws IOException {
        // Arrange
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
        when(httpResponse.getCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);

        // Act
        boolean result = statusListClient.publishTokenStatus("token123", "LOGIN");

        // Assert
        assertFalse(result);
        verify(httpClient, times(1)).execute(any(HttpPost.class));
    }

    @Test
    public void testStatusListClient_ValidateStatusRecord_MissingCredentialId() {
        // Arrange
        TokenStatusRecord record = new TokenStatusRecord();
        record.setIssuerId("test-issuer");

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> statusListClient.publishRecord(record));
    }

    @Test
    public void testStatusListService_PublishRecord_Success() throws Exception {
        // Arrange
        TokenStatusRecord record = createValidStatusRecord();
        Field httpClientField = StatusListService.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        java.net.http.HttpClient mockHttpClient = (java.net.http.HttpClient) httpClientField.get(statusListService);

        HttpResponse<String> mockResponse = mockHttpResponse(HttpStatus.SC_OK, "{}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // Act
        statusListService.publishRecord(record);

        // Assert
        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    public void testStatusListService_PublishRecord_RetryOnFailure() throws Exception {
        // Arrange
        TokenStatusRecord record = createValidStatusRecord();
        Field httpClientField = StatusListService.class.getDeclaredField("httpClient");
        httpClientField.setAccessible(true);
        java.net.http.HttpClient mockHttpClient = (java.net.http.HttpClient) httpClientField.get(statusListService);

        HttpResponse<String> mockSuccessResponse = mockHttpResponse(HttpStatus.SC_OK, "{}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Connection failed"))
                .thenThrow(new IOException("Connection failed"))
                .thenReturn(mockSuccessResponse);

        // Act
        statusListService.publishRecord(record);

        // Assert
        verify(mockHttpClient, times(3)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    public void testTokenStatusEventListenerProvider_LoginEvent() throws StatusListException, NoSuchFieldException, IllegalAccessException {
        // Arrange
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setSessionId("session123");
        event.setRealmId("test-realm");
        event.setClientId("test-client");
        event.setUserId("user123");
        Map<String, String> details = new HashMap<>();
        details.put("exp", String.valueOf(Instant.now().plusSeconds(3600).getEpochSecond()));
        event.setDetails(details);

        RealmProvider realmProvider = mock(RealmProvider.class);
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("test-realm")).thenReturn(realm);

        // Mock StatusListService to avoid real HTTP calls
        StatusListService mockService = mock(StatusListService.class);
        Field serviceField = TokenStatusEventListenerProvider.class.getDeclaredField("statusListService");
        serviceField.setAccessible(true);
        serviceField.set(eventListenerProvider, mockService);

        // Act
        eventListenerProvider.onEvent(event);

        // Assert
        verify(mockService, times(1)).publishRecord(any(TokenStatusRecord.class));
        verify(session, atLeastOnce()).getContext();
    }

    @Test
    public void testTokenStatusEventListenerProvider_LogoutEvent() throws StatusListException, NoSuchFieldException, IllegalAccessException {
        // Arrange
        Event event = new Event();
        event.setType(EventType.LOGOUT);
        event.setSessionId("session123");
        event.setRealmId("test-realm");
        event.setClientId("test-client");
        event.setUserId("user123");
        Map<String, String> details = new HashMap<>();
        details.put("exp", String.valueOf(Instant.now().plusSeconds(3600).getEpochSecond()));
        event.setDetails(details);

        RealmProvider realmProvider = mock(RealmProvider.class);
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("test-realm")).thenReturn(realm);

        // Mock StatusListService to avoid real HTTP calls
        StatusListService mockService = mock(StatusListService.class);
        Field serviceField = TokenStatusEventListenerProvider.class.getDeclaredField("statusListService");
        serviceField.setAccessible(true);
        serviceField.set(eventListenerProvider, mockService);

        // Act
        eventListenerProvider.onEvent(event);

        // Assert
        verify(mockService, times(1)).publishRecord(any(TokenStatusRecord.class));
        verify(session, atLeastOnce()).getContext();
    }

    @Test
    public void testTokenStatusEventListenerProvider_DisabledConfig() throws NoSuchFieldException, StatusListException, IllegalAccessException {
        // Arrange
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setSessionId("session123");
        event.setRealmId("test-realm");
        Map<String, String> details = new HashMap<>();
        Map<String, String> details1 = details;

        StatusListConfig config = mock(StatusListConfig.class);
        when(config.isEnabled()).thenReturn(false);

        RealmProvider realmProvider = mock(RealmProvider.class);
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealm("test-realm")).thenReturn(realm);

        // Mock StatusListService to avoid real HTTP calls
        StatusListService mockService = mock(StatusListService.class);
        Field serviceField = TokenStatusEventListenerProvider.class.getDeclaredField("statusListService");
        serviceField.setAccessible(true);
        serviceField.set(eventListenerProvider, mockService);

        // Act
        eventListenerProvider.onEvent(event);

        // Assert
        verify(mockService, never()).publishRecord(any(TokenStatusRecord.class));
        verify(session, atLeastOnce()).getContext();
    }

    private TokenStatusRecord createValidStatusRecord() {
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId("token123");
        record.setIssuerId("test-issuer");
        record.setPublicKey("MIIBIjANBgkqhki...");
        record.setAlg("RS256");
        record.setStatus(TokenStatus.VALID);
        record.setIssuedAt(Instant.now());
        record.setExpiresAt(Instant.now().plusSeconds(3600));
        record.setCredentialType("oauth2");
        return record;
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockHttpResponse(int statusCode, String body) {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(statusCode);
        when(response.body()).thenReturn(body);
        when(response.headers()).thenReturn(java.net.http.HttpHeaders.of(new HashMap<>(), (k, v) -> true));
        return response;
    }
}