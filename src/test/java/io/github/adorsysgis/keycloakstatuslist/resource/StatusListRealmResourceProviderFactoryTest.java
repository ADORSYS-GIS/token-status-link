package io.github.adorsysgis.keycloakstatuslist.resource;

import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.STATUS_LIST_ENABLED;
import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.STATUS_LIST_SERVER_URL;
import static io.github.adorsysgis.keycloakstatuslist.service.RealmAsIssuerRegistrationService.BACKOFF_MULTIPLIER_MS;
import static io.github.adorsysgis.keycloakstatuslist.service.RealmAsIssuerRegistrationService.DEFAULT_INITIAL_DELAY_MS;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import io.github.adorsysgis.keycloakstatuslist.service.CryptoIdentityService;
import io.github.adorsysgis.keycloakstatuslist.service.RealmAsIssuerRegistrationService;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEventListener;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

class StatusListRealmResourceProviderFactoryTest extends MockKeycloakTest {

    @Mock
    private ScheduledExecutorService recordingScheduler;

    private StatusListServiceStub statusListServiceStub;
    private MockedStatic<CryptoIdentityService> mockedCryptoIdentityStatic;
    private MockedConstruction<StatusListService> mockedStatusListServiceConstruction;
    private MockedConstruction<CryptoIdentityService> mockedCryptoServiceConstruction;

    private StatusListRealmResourceProviderFactory factory;
    private RealmAsIssuerRegistrationService registrationService;

    @BeforeEach
    void setUp() {
        statusListServiceStub = service -> when(service.checkServerHealth()).thenReturn(true);
        registrationService = new TestRegistrationService();
        factory = new StatusListRealmResourceProviderFactory() {
            @Override
            protected RealmAsIssuerRegistrationService createRegistrationService(KeycloakSessionFactory factory) {
                return registrationService;
            }
        };

        lenient().when(session.realms()).thenReturn(realmProvider);
        lenient().when(realmProvider.getRealmByName(TEST_REALM_NAME)).thenReturn(realm);
        lenient().when(realm.getAttribute(STATUS_LIST_ENABLED)).thenReturn("true");
        lenient().when(realm.getAttribute(STATUS_LIST_SERVER_URL)).thenReturn("http://localhost:8080");

        mockedCryptoIdentityStatic = mockStatic(CryptoIdentityService.class);
        mockedCryptoIdentityStatic
                .when(() -> CryptoIdentityService.getRealmKeyData(any(), any()))
                .thenReturn(new CryptoIdentityService.KeyData(mock(JWK.class), "RS256"));

        mockedCryptoServiceConstruction =
                mockConstruction(CryptoIdentityService.class, (self, selfContext) -> when(self.getJwtToken(any()))
                        .thenReturn("mock-token"));

        mockedStatusListServiceConstruction =
                mockConstruction(StatusListService.class, (self, selfContext) -> statusListServiceStub.configure(self));
    }

    @AfterEach
    void tearDown() {
        mockedCryptoIdentityStatic.close();
        mockedCryptoServiceConstruction.close();
        mockedStatusListServiceConstruction.close();
    }

    private List<StatusListService> constructed() {
        return mockedStatusListServiceConstruction.constructed();
    }

    private void triggerBackground(long initialDelay, int maxRetries) {
        registrationService.triggerBackgroundRegistration(TEST_REALM_NAME, initialDelay, maxRetries);
    }

    /** Immediate trigger: the attempt runnable can be observed right away on the test thread. */
    private void triggerImmediate() {
        triggerBackground(0L, 0);
    }

    @Test
    void testPostMigrationEventSchedulesDefaultRegistrationForListedRealms() throws StatusListException {
        RealmModel otherRealm = mock(RealmModel.class);
        lenient().when(otherRealm.getName()).thenReturn("other-realm");
        lenient().when(otherRealm.getAttribute(STATUS_LIST_ENABLED)).thenReturn("true");
        lenient().when(otherRealm.getAttribute(STATUS_LIST_SERVER_URL)).thenReturn("http://localhost:8080");
        lenient().when(realmProvider.getRealmByName("other-realm")).thenReturn(otherRealm);
        lenient().when(realmProvider.getRealmsStream()).thenReturn(Stream.of(realm, otherRealm));

        firePostInitEvent(new PostMigrationEvent(sessionFactory));

        // Default trigger path: all listed realms are scheduled once with the 1s initial delay
        verify(recordingScheduler, times(2))
                .schedule(any(Runnable.class), eq(DEFAULT_INITIAL_DELAY_MS), eq(TimeUnit.MILLISECONDS));
        runAllScheduledInDefaultDelay();
        List<StatusListService> services = constructed();
        assertEquals(2, services.size());
        verify(services.get(0)).registerIssuer(argThat(issuerId -> issuerId.endsWith("::" + TEST_REALM_NAME)), any());
        verify(services.get(1)).registerIssuer(argThat(issuerId -> issuerId.endsWith("::other-realm")), any());
    }

    @Test
    void testRealmPostCreateEventTriggersDefaultRegistration() throws StatusListException {
        RealmModel.RealmPostCreateEvent event = mock(RealmModel.RealmPostCreateEvent.class);
        when(event.getCreatedRealm()).thenReturn(realm);

        firePostInitEvent(event);

        // New realm registration is triggered with the default 1s initial delay
        verify(recordingScheduler, times(1))
                .schedule(any(Runnable.class), eq(DEFAULT_INITIAL_DELAY_MS), eq(TimeUnit.MILLISECONDS));
        runScheduled(DEFAULT_INITIAL_DELAY_MS);
        StatusListService service = constructed().get(0);
        verify(service).registerIssuer(argThat(issuerId -> issuerId.endsWith("::" + TEST_REALM_NAME)), any());
    }

    @Test
    void testSuccessfulImmediateTrigger() throws StatusListException {
        factory.postInit(sessionFactory);
        triggerImmediate();

        runScheduled(0L);

        StatusListService service = constructed().get(0);
        verify(service).checkServerHealth();
        verify(service).registerIssuer(argThat(issuerId -> issuerId.endsWith("::" + TEST_REALM_NAME)), any());
        // Successful attempt: no further retries are scheduled
        verifyNoMoreInteractions(recordingScheduler);
    }

    @Test
    void testRegistrationStopsWhenRealmNoLongerExists() {
        triggerImmediate();
        lenient().when(realmProvider.getRealmByName(TEST_REALM_NAME)).thenReturn(null);

        runScheduled(0L);
        assertEquals(0, constructed().size());
        verifyNoMoreInteractions(recordingScheduler);
    }

    @Test
    void testFailedRegistrationIsRescheduledWithGrowingDelayWithinBudget() {
        stubFailingRegistration();

        // Re-trigger with a 2-retry budget: attempt 0 fails, retry in 10s; attempt 1 fails, in 20s
        triggerBackground(30_000L, 2);
        runScheduled(30_000L);
        runScheduled(BACKOFF_MULTIPLIER_MS);
        runScheduled(2 * BACKOFF_MULTIPLIER_MS); // attempt 2 exhausts the budget: no further scheduling happens

        verify(recordingScheduler, times(3)).schedule(any(Runnable.class), anyLong(), eq(TimeUnit.MILLISECONDS));
        verifyNoMoreInteractions(recordingScheduler);
    }

    @Test
    void testFailingRegistrationAfterBudgetIsPickedUpByNextTrigger() {
        stubFailingRegistration();

        // Exhaust the 0-retry budget: no rescheduling after the failing attempt
        triggerImmediate();
        runScheduled(0L);
        verifyNoMoreInteractions(recordingScheduler);

        // New trigger passes: a second registration run is scheduled (budget was exhausted)
        triggerImmediate();
        runScheduled(0L);
        assertEquals(2, constructed().size());
    }

    @Test
    void testUnhealthyStatusListServerSkipsIssuerRegistration() throws StatusListException {
        statusListServiceStub = service -> when(service.checkServerHealth()).thenReturn(false);
        triggerImmediate();

        runScheduled(0L);

        StatusListService service = constructed().get(0);
        verify(service).checkServerHealth();
        verify(service, never()).registerIssuer(any(), any());
    }

    @Test
    void testKeyExtractionFailureLeavesAttemptForgottenAfterBudget() {
        triggerImmediate();
        mockedCryptoIdentityStatic
                .when(() -> CryptoIdentityService.getRealmKeyData(any(), any()))
                .thenThrow(new StatusListException("Key not found"));

        runScheduled(0L);
        assertEquals(0, constructed().size());
        verifyNoMoreInteractions(recordingScheduler);
    }

    @Test
    void testCloseDecommissionsScheduler() {
        factory.postInit(sessionFactory);
        factory.close();

        verify(recordingScheduler).shutdownNow();
    }

    /** Runs the most recently scheduled attempt runnable whose delay matches the given one. */
    private void runScheduled(long delayMs) {
        ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
        verify(recordingScheduler, atLeastOnce()).schedule(captor.capture(), eq(delayMs), eq(TimeUnit.MILLISECONDS));
        List<Runnable> all = captor.getAllValues();
        all.get(all.size() - 1).run();
    }

    /** Runs every scheduled attempt runnable with the given delay, in scheduling order. */
    private void runAllScheduledInDefaultDelay() {
        ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
        verify(recordingScheduler, atLeastOnce())
                .schedule(captor.capture(), eq(DEFAULT_INITIAL_DELAY_MS), eq(TimeUnit.MILLISECONDS));
        captor.getAllValues().forEach(Runnable::run);
    }

    /** Runs postInit and dispatches the given event to the registered provider event listener. */
    private void firePostInitEvent(org.keycloak.provider.ProviderEvent event) {
        factory.postInit(sessionFactory);
        ArgumentCaptor<ProviderEventListener> listenerCaptor = ArgumentCaptor.forClass(ProviderEventListener.class);
        verify(sessionFactory, atLeastOnce()).register(listenerCaptor.capture());
        assertDoesNotThrow(() -> listenerCaptor.getValue().onEvent(event));
    }

    private void stubFailingRegistration() {
        statusListServiceStub = service -> {
            when(service.checkServerHealth()).thenReturn(true);
            doThrow(new StatusListException("registration failed"))
                    .when(service)
                    .registerIssuer(any(), any());
        };
    }

    @FunctionalInterface
    private interface StatusListServiceStub {
        void configure(StatusListService service) throws StatusListException;
    }

    /** Test service: recordings instead of real background scheduling and HTTP clients. */
    private class TestRegistrationService extends RealmAsIssuerRegistrationService {
        TestRegistrationService() {
            super(sessionFactory);
        }

        @Override
        protected ScheduledExecutorService createScheduler() {
            return recordingScheduler;
        }

        @Override
        protected CloseableHttpClient registrationClient(StatusListConfig config) {
            return httpClient;
        }
    }
}
