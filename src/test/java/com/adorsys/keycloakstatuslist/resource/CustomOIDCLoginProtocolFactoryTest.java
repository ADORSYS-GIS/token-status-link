package com.adorsys.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.CryptoIdentityService;
import com.adorsys.keycloakstatuslist.service.CustomHttpClient;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.EntityManager;
import java.io.IOException;
import java.util.stream.Stream;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEventListener;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

class CustomOIDCLoginProtocolFactoryTest {

    private CustomOIDCLoginProtocolFactory factory;
    private KeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private KeycloakTransactionManager transactionManager;
    private RealmProvider realmProvider;
    private RealmModel realm;
    private JpaConnectionProvider jpaConnectionProvider;
    private EntityManager entityManager;

    private MockedStatic<CryptoIdentityService> mockedRevocationService;
    private MockedStatic<CustomHttpClient> mockedHttpClient;

    private MockedConstruction<StatusListService> mockedStatusListServiceConstruction;
    private MockedConstruction<CryptoIdentityService> mockedCryptoServiceConstruction;

    @BeforeEach
    void setUp() {
        factory = new CustomOIDCLoginProtocolFactory() {
            @Override
            protected void runAsync(Runnable runnable) {
                runnable.run();
            }
        };
        sessionFactory = mock(KeycloakSessionFactory.class);
        session = mock(KeycloakSession.class);
        KeycloakContext context1 = mock(KeycloakContext.class);
        transactionManager = mock(KeycloakTransactionManager.class);
        realmProvider = mock(RealmProvider.class);
        realm = mock(RealmModel.class);
        jpaConnectionProvider = mock(JpaConnectionProvider.class);
        entityManager = mock(EntityManager.class);

        when(session.getContext()).thenReturn(context1);
        lenient().when(context1.getRealm()).thenReturn(realm);

        when(sessionFactory.create()).thenReturn(session);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(session.getTransactionManager()).thenReturn(transactionManager);
        when(session.realms()).thenReturn(realmProvider);
        when(session.getProvider(eq(JpaConnectionProvider.class))).thenReturn(jpaConnectionProvider);
        when(jpaConnectionProvider.getEntityManager()).thenReturn(entityManager);
        when(realmProvider.getRealmsStream()).thenAnswer(i -> Stream.of(realm));
        lenient().when(realmProvider.getRealmByName("test-realm")).thenReturn(realm);

        when(realm.getName()).thenReturn("test-realm");
        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        when(realm.getAttribute("status-list-server-url")).thenReturn("http://localhost:8080");

        mockedRevocationService = mockStatic(CryptoIdentityService.class);
        mockedHttpClient = mockStatic(CustomHttpClient.class);

        mockedStatusListServiceConstruction =
                mockConstruction(StatusListService.class, (mock, context) -> when(mock.checkServerHealth())
                        .thenReturn(true));
        mockedCryptoServiceConstruction =
                mockConstruction(CryptoIdentityService.class, (mock, context) -> when(mock.getJwtToken(any()))
                        .thenReturn("mock-token"));

        JWK mockJwk = mock(JWK.class);
        CryptoIdentityService.KeyData keyData = new CryptoIdentityService.KeyData(mockJwk, "RS256");
        mockedRevocationService
                .when(() -> CryptoIdentityService.getRealmKeyData(any(), any()))
                .thenReturn(keyData);
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
        assertInstanceOf(CustomOIDCLoginProtocolService.class, endpoint);
    }

    @Test
    void testPostInitRegistersListenerAndProcessesRealms() throws IOException {
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);

        mockedHttpClient
                .when(() -> CustomHttpClient.getRegistrationHttpClient(any(StatusListConfig.class)))
                .thenReturn(httpClient);

        when(httpClient.execute(
                        any(HttpGet.class), org.mockito.ArgumentMatchers.<HttpClientResponseHandler<Boolean>>any()))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Boolean> handler = invocation.getArgument(1);
                    when(httpResponse.getCode()).thenReturn(200);
                    when(httpResponse.getEntity()).thenReturn(new StringEntity("OK"));
                    return handler.handleResponse(httpResponse);
                });

        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);

        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());

        listenerCaptor.getValue().onEvent(new PostMigrationEvent(sessionFactory));

        verify(transactionManager).begin();
        verify(transactionManager).commit();

        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
        StatusListService mockService =
                mockedStatusListServiceConstruction.constructed().get(0);

        try {
            verify(mockService).registerIssuer(argThat(arg -> arg.endsWith("::test-realm")), any());
        } catch (StatusListException e) {
            fail("Should not throw exception");
        }
    }

    @Test
    void testLazyRegistrationInCreateProtocolEndpoint() {
        // Ensure not registered initially
        factory.createProtocolEndpoint(session, mock(EventBuilder.class));

        StatusListService lastMock = mockedStatusListServiceConstruction
                .constructed()
                .get(mockedStatusListServiceConstruction.constructed().size() - 1);
        try {
            verify(lastMock).registerIssuer(argThat(arg -> arg.endsWith("::test-realm")), any());
        } catch (StatusListException e) {
            fail("Should not throw exception");
        }
    }

    @Test
    void testInitializeRealms_SkippedWhenDisabled() {
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        triggerInitialization();

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());
        mockedHttpClient.verify(() -> CustomHttpClient.getRegistrationHttpClient(any(StatusListConfig.class)), never());
    }

    @Test
    void testInitializeRealms_SkippedWhenHealthCheckFails() throws IOException {
        // We need to override the default mock behavior for this test
        mockedStatusListServiceConstruction.close();
        mockedStatusListServiceConstruction =
                mockConstruction(StatusListService.class, (mock, context) -> when(mock.checkServerHealth())
                        .thenReturn(false));

        triggerInitialization();

        // Service is constructed but registration is skipped
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
        StatusListService mockService =
                mockedStatusListServiceConstruction.constructed().get(0);

        try {
            verify(mockService, never()).registerIssuer(any(), any());
        } catch (StatusListException e) {
            fail("Should not throw exception");
        }
    }

    @Test
    void testInitializeRealms_SkippedWhenKeyExtractionFails() throws Exception {
        setupSuccessfulHealthCheck();

        mockedRevocationService
                .when(() -> CryptoIdentityService.getRealmKeyData(session, realm))
                .thenThrow(new StatusListException("Key not found"));

        triggerInitialization();

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_HandlesAlreadyRegisteredMap() {
        setupSuccessfulHealthCheck();
        CryptoIdentityService.KeyData keyData = new CryptoIdentityService.KeyData(mock(JWK.class), "RS256");
        mockedRevocationService
                .when(() -> CryptoIdentityService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        triggerInitialization();
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());

        triggerInitialization();
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_GracefulFailureOnServiceException() {
        setupSuccessfulHealthCheck();

        CryptoIdentityService.KeyData keyData = new CryptoIdentityService.KeyData(mock(JWK.class), "RS256");
        mockedRevocationService
                .when(() -> CryptoIdentityService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        triggerInitialization();

        StatusListService mockService =
                mockedStatusListServiceConstruction.constructed().get(0);
        try {
            doThrow(new RuntimeException("API Error")).when(mockService).registerIssuer(any(), any());
        } catch (StatusListException e) {
            fail("Should not throw exception during setup");
        }

        assertDoesNotThrow(this::triggerInitialization);
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
            mockedHttpClient
                    .when(() -> CustomHttpClient.getRegistrationHttpClient(any(StatusListConfig.class)))
                    .thenReturn(httpClient);

            when(httpClient.execute(
                            any(HttpGet.class), org.mockito.ArgumentMatchers.<HttpClientResponseHandler<Boolean>>any()))
                    .thenAnswer(invocation -> {
                        HttpClientResponseHandler<Boolean> handler = invocation.getArgument(1);
                        when(httpResponse.getCode()).thenReturn(200);
                        when(httpResponse.getEntity()).thenReturn(new StringEntity("OK"));
                        return handler.handleResponse(httpResponse);
                    });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
