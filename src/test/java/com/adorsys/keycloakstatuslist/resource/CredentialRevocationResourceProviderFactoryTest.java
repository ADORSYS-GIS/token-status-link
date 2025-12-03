package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.RevocationRecordService;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.*;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEventListener;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialRevocationResourceProviderFactoryTest {

    private CredentialRevocationResourceProviderFactory factory;
    private KeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private KeycloakContext context; // Added context mock
    private KeycloakTransactionManager transactionManager;
    private RealmProvider realmProvider;
    private RealmModel realm;

    private MockedStatic<RevocationRecordService> mockedRevocationService;
    private MockedStatic<CustomHttpClient> mockedHttpClient;

    private MockedConstruction<StatusListService> mockedStatusListServiceConstruction;
    private MockedConstruction<CryptoIdentityService> mockedCryptoServiceConstruction;

    @BeforeEach
    void setUp() {
        factory = new CredentialRevocationResourceProviderFactory();
        sessionFactory = mock(KeycloakSessionFactory.class);
        session = mock(KeycloakSession.class);
        context = mock(KeycloakContext.class); // Init context mock
        transactionManager = mock(KeycloakTransactionManager.class);
        realmProvider = mock(RealmProvider.class);
        realm = mock(RealmModel.class);

        // FIX NPE: Setup Session Context
        when(session.getContext()).thenReturn(context);
        // Ensure context returns the realm when asked (needed for ProtocolEndpoint creation)
        lenient().when(context.getRealm()).thenReturn(realm);

        when(sessionFactory.create()).thenReturn(session);
        when(session.getTransactionManager()).thenReturn(transactionManager);
        when(session.realms()).thenReturn(realmProvider);
        when(realmProvider.getRealmsStream()).thenAnswer(i -> Stream.of(realm));

        when(realm.getName()).thenReturn("test-realm");
        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8080");

        mockedRevocationService = mockStatic(RevocationRecordService.class);
        mockedHttpClient = mockStatic(CustomHttpClient.class);

        mockedStatusListServiceConstruction = mockConstruction(StatusListService.class);
        mockedCryptoServiceConstruction = mockConstruction(CryptoIdentityService.class,
                (mock, context) -> when(mock.getJwtToken(any())).thenReturn("mock-token"));
    }

    @AfterEach
    void tearDown() {
        if (mockedRevocationService != null) mockedRevocationService.close();
        if (mockedHttpClient != null) mockedHttpClient.close();
        if (mockedStatusListServiceConstruction != null) mockedStatusListServiceConstruction.close();
        if (mockedCryptoServiceConstruction != null) mockedCryptoServiceConstruction.close();
        
        factory.close();
    }

    @Test
    void testProtocolEndpointCreation() {
        Object endpoint = factory.createProtocolEndpoint(session, mock(EventBuilder.class));
        assertNotNull(endpoint);
        assertTrue(endpoint instanceof CustomOIDCLoginProtocolService);
    }

    @Test
    void testPostInitRegistersListenerAndProcessesRealms() throws IOException {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
        
        mockedHttpClient.when(CustomHttpClient::getHttpClient).thenReturn(httpClient);

        when(httpClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
            HttpClientResponseHandler<?> handler = invocation.getArgument(1);
            when(httpResponse.getCode()).thenReturn(200);
            when(httpResponse.getEntity()).thenReturn(new StringEntity("OK"));
            return handler.handleResponse(httpResponse);
        });

        JWK mockJwk = mock(JWK.class);
        RevocationRecordService.KeyData keyData = new RevocationRecordService.KeyData(mockJwk, "RS256");
        mockedRevocationService.when(() -> RevocationRecordService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        // TRIGGER
        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);
        
        // FIX: Use atLeastOnce() because super.postInit also registers a listener
        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());

        // listenerCaptor.getValue() returns the *last* captured value, which is ours
        listenerCaptor.getValue().onEvent(new PostMigrationEvent(sessionFactory));

        verify(transactionManager).begin();
        verify(transactionManager).commit();

        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
        StatusListService mockService = mockedStatusListServiceConstruction.constructed().get(0);
        
        verify(mockService).registerIssuer("http://localhost:8080/realms/test-realm", mockJwk, "RS256");
    }

    @Test
    void testInitializeRealms_SkippedWhenDisabled() {
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        triggerInitialization();

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());
        mockedHttpClient.verify(CustomHttpClient::getHttpClient, never());
    }

    @Test
    void testInitializeRealms_SkippedWhenHealthCheckFails() throws IOException {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
        mockedHttpClient.when(CustomHttpClient::getHttpClient).thenReturn(httpClient);
        
        when(httpClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
            HttpClientResponseHandler<?> handler = invocation.getArgument(1);
            when(httpResponse.getCode()).thenReturn(500); 
            when(httpResponse.getEntity()).thenReturn(new StringEntity("Error"));
            return handler.handleResponse(httpResponse);
        });

        triggerInitialization();

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_SkippedWhenKeyExtractionFails() throws Exception {
        setupSuccessfulHealthCheck();

        mockedRevocationService.when(() -> RevocationRecordService.getRealmKeyData(session, realm))
                .thenThrow(new com.adorsys.keycloakstatuslist.exception.StatusListException("Key not found"));

        triggerInitialization();

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_HandlesAlreadyRegisteredMap() {
        setupSuccessfulHealthCheck();
        RevocationRecordService.KeyData keyData = new RevocationRecordService.KeyData(mock(JWK.class), "RS256");
        mockedRevocationService.when(() -> RevocationRecordService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        triggerInitialization();
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());

        triggerInitialization();
        // Should remain 1 because realm is already registered
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_GracefulFailureOnServiceException() {
        setupSuccessfulHealthCheck();
        
        RevocationRecordService.KeyData keyData = new RevocationRecordService.KeyData(mock(JWK.class), "RS256");
        mockedRevocationService.when(() -> RevocationRecordService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        triggerInitialization();

        StatusListService mockService = mockedStatusListServiceConstruction.constructed().get(0);
        doThrow(new RuntimeException("API Error")).when(mockService).registerIssuer(any(), any(), any());

        assertDoesNotThrow(() -> triggerInitialization());
    }

    private void triggerInitialization() {
        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);
        
        // FIX: Use atLeastOnce() to handle multiple register calls from super classes
        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());
        
        // The last captured listener is the one registered by CredentialRevocationResourceProviderFactory
        listenerCaptor.getValue().onEvent(new PostMigrationEvent(sessionFactory));
    }

    private void setupSuccessfulHealthCheck() {
        try {
            CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
            CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
            mockedHttpClient.when(CustomHttpClient::getHttpClient).thenReturn(httpClient);
            
            when(httpClient.execute(any(HttpGet.class), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
                HttpClientResponseHandler<?> handler = invocation.getArgument(1);
                when(httpResponse.getCode()).thenReturn(200);
                when(httpResponse.getEntity()).thenReturn(new StringEntity("OK"));
                return handler.handleResponse(httpResponse);
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}