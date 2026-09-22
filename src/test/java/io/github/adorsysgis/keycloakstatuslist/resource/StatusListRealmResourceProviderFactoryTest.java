package io.github.adorsysgis.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
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

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.service.CircuitBreaker;
import io.github.adorsysgis.keycloakstatuslist.service.CryptoIdentityService;
import io.github.adorsysgis.keycloakstatuslist.service.CustomHttpClient;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService;
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
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.timer.TimerProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

class StatusListRealmResourceProviderFactoryTest {

    private StatusListRealmResourceProviderFactory factory;
    private KeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private KeycloakTransactionManager transactionManager;
    private RealmProvider realmProvider;
    private RealmModel realm;
    private TimerProvider timerProvider;
    private JpaConnectionProvider jpaConnectionProvider;
    private EntityManager entityManager;

    private MockedStatic<CryptoIdentityService> mockedRevocationService;
    private MockedStatic<CustomHttpClient> mockedHttpClient;

    private MockedConstruction<StatusListService> mockedStatusListServiceConstruction;
    private MockedConstruction<CryptoIdentityService> mockedCryptoServiceConstruction;
    private MockedStatic<CircuitBreaker> mockedCircuitBreaker;

    @BeforeEach
    void setUp() {
        mockedCircuitBreaker = mockStatic(CircuitBreaker.class);
        mockedCircuitBreaker
                .when(() -> CircuitBreaker.getInstance(any(), anyInt(), anyInt(), anyInt()))
                .thenAnswer(inv -> mock(CircuitBreaker.class));
        mockedCircuitBreaker
                .when(() -> CircuitBreaker.getInstance(any(StatusListConfig.class)))
                .thenReturn(mock(CircuitBreaker.class));

        factory = new StatusListRealmResourceProviderFactory() {
            @Override
            protected void runAsync(Runnable runnable) {
                runnable.run();
            }
        };
        sessionFactory = mock(KeycloakSessionFactory.class);
        session = mock(KeycloakSession.class);
        KeycloakContext context1 = mock(KeycloakContext.class);
        ClientConnection connection = mock(ClientConnection.class);
        transactionManager = mock(KeycloakTransactionManager.class);
        realmProvider = mock(RealmProvider.class);
        realm = mock(RealmModel.class);
        timerProvider = mock(TimerProvider.class);
        jpaConnectionProvider = mock(JpaConnectionProvider.class);
        entityManager = mock(EntityManager.class);

        when(session.getContext()).thenReturn(context1);
        lenient().when(context1.getRealm()).thenReturn(realm);
        lenient().when(context1.getConnection()).thenReturn(connection);

        when(sessionFactory.create()).thenReturn(session);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(session.getTransactionManager()).thenReturn(transactionManager);
        when(session.realms()).thenReturn(realmProvider);
        when(session.getProvider(TimerProvider.class)).thenReturn(timerProvider);
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
        if (mockedCircuitBreaker != null) mockedCircuitBreaker.close();

        factory.close();
    }

    @Test
    void testRealmResourceCreation() {
        StatusListRealmResourceProvider provider = (StatusListRealmResourceProvider) factory.create(session);
        assertNotNull(provider);
        Object resource = provider.getResource();
        assertNotNull(resource);
        assertInstanceOf(StatusListRealmResourceProvider.class, resource);
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
        runReconciliation();

        verify(transactionManager, atLeastOnce()).begin();
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
    void testLazyRegistrationInResourceAccess() {
        // Ensure not registered initially
        StatusListRealmResourceProvider provider = (StatusListRealmResourceProvider) factory.create(session);
        provider.getResource();

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
    void testLazyRegistration_RollsBackWhenRealmLookupFails() {
        when(transactionManager.isActive()).thenReturn(true);
        when(realmProvider.getRealmByName("test-realm")).thenThrow(new RuntimeException("realm lookup failed"));

        assertDoesNotThrow(() -> {
            StatusListRealmResourceProvider provider = (StatusListRealmResourceProvider) factory.create(session);
            provider.getResource();
        });

        verify(transactionManager).rollback();
        verify(transactionManager, never()).commit();
    }

    @Test
    void testInitializeRealms_SkippedWhenDisabled() {
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        triggerInitialization();
        runReconciliation();

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
        runReconciliation();

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
        runReconciliation();

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
        runReconciliation();
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());

        triggerInitialization();
        runReconciliation();
        assertEquals(1, mockedStatusListServiceConstruction.constructed().size());
    }

    @Test
    void testInitializeRealms_GracefulFailureOnServiceException() {
        setupSuccessfulHealthCheck();

        mockedStatusListServiceConstruction.close();
        mockedStatusListServiceConstruction = mockConstruction(StatusListService.class, (mock, context) -> {
            when(mock.checkServerHealth()).thenReturn(true);
            try {
                doThrow(new RuntimeException("API Error")).when(mock).registerIssuer(any(), any());
            } catch (StatusListException e) {
                fail("Should not throw while configuring the mock");
            }
        });

        CryptoIdentityService.KeyData keyData = new CryptoIdentityService.KeyData(mock(JWK.class), "RS256");
        mockedRevocationService
                .when(() -> CryptoIdentityService.getRealmKeyData(session, realm))
                .thenReturn(keyData);

        triggerInitialization();
        assertDoesNotThrow(this::runReconciliation);
    }

    @Test
    void testRegistrationReconciliationRetriesRealmConfiguredAfterStartup() throws Exception {
        setupSuccessfulHealthCheck();

        when(session.getProvider(TimerProvider.class)).thenReturn(timerProvider);
        when(realm.getAttribute("status-list-enabled")).thenReturn("false");

        triggerInitialization();

        ArgumentCaptor<ScheduledTask> taskCaptor = ArgumentCaptor.forClass(ScheduledTask.class);
        verify(timerProvider)
                .scheduleTask(
                        taskCaptor.capture(),
                        eq(1_000L),
                        eq(30_000L),
                        eq("status-list-realm-registration-reconciliation"));

        assertEquals(0, mockedStatusListServiceConstruction.constructed().size());

        when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        taskCaptor.getValue().run(session);

        StatusListService mockService =
                mockedStatusListServiceConstruction.constructed().get(0);
        verify(mockService).registerIssuer(argThat(arg -> arg.endsWith("::test-realm")), any());
    }

    @Test
    void testRegistrationReconciliationStopsAfterFiveAttempts() throws Exception {
        setupSuccessfulHealthCheck();

        mockedStatusListServiceConstruction.close();
        mockedStatusListServiceConstruction = mockConstruction(StatusListService.class, (mock, context) -> {
            when(mock.checkServerHealth()).thenReturn(true);
            try {
                doThrow(new StatusListException("registration failed"))
                        .when(mock)
                        .registerIssuer(any(), any());
            } catch (StatusListException e) {
                fail("Should not throw while configuring the mock");
            }
        });

        triggerInitialization();
        ArgumentCaptor<ScheduledTask> taskCaptor = ArgumentCaptor.forClass(ScheduledTask.class);
        verify(timerProvider)
                .scheduleTask(
                        taskCaptor.capture(),
                        eq(1_000L),
                        eq(30_000L),
                        eq("status-list-realm-registration-reconciliation"));

        for (int attempt = 0; attempt < 6; attempt++) {
            taskCaptor.getValue().run(session);
        }

        assertEquals(5, mockedStatusListServiceConstruction.constructed().size());
    }

    private void triggerInitialization() {
        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        factory.postInit(sessionFactory);

        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());

        listenerCaptor.getValue().onEvent(new PostMigrationEvent(sessionFactory));
    }

    private void runReconciliation() {
        ArgumentCaptor<ScheduledTask> taskCaptor = ArgumentCaptor.forClass(ScheduledTask.class);
        verify(timerProvider)
                .scheduleTask(
                        taskCaptor.capture(),
                        eq(1_000L),
                        eq(30_000L),
                        eq("status-list-realm-registration-reconciliation"));
        taskCaptor.getValue().run(session);
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
