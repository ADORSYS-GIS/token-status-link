package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.RevocationRecordService;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.EntityManager;
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
import org.keycloak.connections.jpa.JpaConnectionProvider;
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
    private KeycloakContext context;
    private KeycloakTransactionManager transactionManager;
    private RealmProvider realmProvider;
    private RealmModel realm;
    private JpaConnectionProvider jpaConnectionProvider;
    private EntityManager entityManager;

    private MockedStatic<RevocationRecordService> mockedRevocationService;
    private MockedStatic<CustomHttpClient> mockedHttpClient;

    private MockedConstruction<StatusListService> mockedStatusListServiceConstruction;
    private MockedConstruction<CryptoIdentityService> mockedCryptoServiceConstruction;

    @BeforeEach
    void setUp() {
        factory = new CredentialRevocationResourceProviderFactory();
        sessionFactory = mock(KeycloakSessionFactory.class);
        session = mock(KeycloakSession.class);
        context = mock(KeycloakContext.class);
        transactionManager = mock(KeycloakTransactionManager.class);
        realmProvider = mock(RealmProvider.class);
        realm = mock(RealmModel.class);
        jpaConnectionProvider = mock(JpaConnectionProvider.class);
        entityManager = mock(EntityManager.class);

        when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);

        when(sessionFactory.create()).thenReturn(session);
        when(session.getTransactionManager()).thenReturn(transactionManager);
        when(session.realms()).thenReturn(realmProvider);
        when(session.getProvider(eq(JpaConnectionProvider.class))).thenReturn(jpaConnectionProvider);
        when(jpaConnectionProvider.getEntityManager()).thenReturn(entityManager);
        when(realmProvider.getRealmsStream()).thenAnswer(i -> Stream.of(realm));

        when(realm.getName()).thenReturn("test-realm");
        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8080");

        mockedRevocationService = mockStatic(RevocationRecordService.class);
        mockedHttpClient = mockStatic(CustomHttpClient.class);

        mockedStatusListServiceConstruction = mockConstruction(StatusListService.class,
                (mock, context) -> when(mock.checkServerHealth()).thenReturn(true));
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

        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);

        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());

        listenerCaptor.getValue().onEvent(new PostMigrationEvent(sessionFactory));

        verify(transactionManager).begin();
        verify(transactionManager).commit();

        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
        StatusListService mockService = mockedStatusListServiceConstruction.constructed().get(0);

        try {
            verify(mockService).registerIssuer(argThat(arg -> arg.endsWith("::test-realm")), eq(mockJwk));
        } catch (StatusListException e) {
            fail("Should not throw exception");
        }
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
        // We need to override the default mock behavior for this test
        mockedStatusListServiceConstruction.close();
        mockedStatusListServiceConstruction = mockConstruction(StatusListService.class,
                (mock, context) -> when(mock.checkServerHealth()).thenReturn(false));

        triggerInitialization();

        // Service is constructed but registration is skipped
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
        StatusListService mockService = mockedStatusListServiceConstruction.constructed().get(0);

        try {
            verify(mockService, never()).registerIssuer(any(), any());
        } catch (StatusListException e) {
            fail("Should not throw exception");
        }
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
        try {
            doThrow(new RuntimeException("API Error")).when(mockService).registerIssuer(any(), any());
        } catch (com.adorsys.keycloakstatuslist.exception.StatusListException e) {
            fail("Should not throw exception during setup");
        }

        assertDoesNotThrow(() -> triggerInitialization());
    }

    private void triggerInitialization() {
        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);

        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());

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