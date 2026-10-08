package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.OVERFLOW_POLICY_REJECT;
import static io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig.OVERFLOW_POLICY_REVOKE_OLDEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceQuotaServiceTest {

    @Mock
    private StatusListRepository statusListRepository;

    @Mock
    private KeycloakSession session;

    @Mock
    private UserProvider userProvider;

    @Mock
    private CredentialRevocationService credentialRevocationService;

    @Mock
    private RealmModel realm;

    @Mock
    private ProtocolMapperModel mapperModel;

    @Mock
    private ClientScopeModel credentialScope;

    @Mock
    private EntityManager entityManager;

    @Mock
    private KeycloakContext context;

    private CredentialIssuanceQuotaService service;

    @BeforeEach
    void setUp() {
        service = new CredentialIssuanceQuotaService(session, statusListRepository, credentialRevocationService);
        lenient().when(realm.getId()).thenReturn("realm-1");
        lenient().when(session.users()).thenReturn(userProvider);
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
    }

    @Test
    void resolveMax_returnsUnlimitedWhenNothingIsConfigured() {
        assertEquals(0, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_usesMapperConfigOverRealmFallback() {
        when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, "2"));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("9");

        assertEquals(2, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_mapperZeroMeansUnlimitedEvenIfRealmHasAFallback() {
        when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, "0"));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("3");

        assertEquals(0, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_usesRealmFallbackWhenMapperConfigIsAbsent() {
        when(mapperModel.getConfig()).thenReturn(Map.of());
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("4");

        assertEquals(4, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_blankMapperConfigFallsBackToRealm() {
        when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, "  "));
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("3");

        assertEquals(3, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_rejectsInvalidMapperConfig() {
        when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, "abc"));

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> service.resolveMax(mapperModel, realm));

        assertTrue(exception.getMessage().contains("abc"));
    }

    @Test
    void resolveOverflowPolicy_defaultsToReject() {
        assertEquals(OVERFLOW_POLICY_REJECT, service.resolveOverflowPolicy(mapperModel, realm));
    }

    @Test
    void resolveOverflowPolicy_usesMapperConfigOverRealmFallback() {
        when(mapperModel.getConfig())
                .thenReturn(Map.of(StatusListConfig.STATUS_LIST_OVERFLOW_POLICY, OVERFLOW_POLICY_REVOKE_OLDEST));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_OVERFLOW_POLICY))
                .thenReturn(OVERFLOW_POLICY_REJECT);

        assertEquals(OVERFLOW_POLICY_REVOKE_OLDEST, service.resolveOverflowPolicy(mapperModel, realm));
    }

    @Test
    void resolveOverflowPolicy_usesRealmFallbackWhenMapperConfigIsAbsent() {
        when(mapperModel.getConfig()).thenReturn(Map.of());
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_OVERFLOW_POLICY))
                .thenReturn(OVERFLOW_POLICY_REVOKE_OLDEST);

        assertEquals(OVERFLOW_POLICY_REVOKE_OLDEST, service.resolveOverflowPolicy(mapperModel, realm));
    }

    @Test
    void resolveMax_rejectsNegativeMapperConfig() {
        when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, "-1"));

        assertThrows(IllegalArgumentException.class, () -> service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_rejectsInvalidRealmFallback() {
        when(mapperModel.getConfig()).thenReturn(Map.of());
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("not-a-number");

        assertThrows(IllegalArgumentException.class, () -> service.resolveMax(mapperModel, realm));
    }

    @Test
    void requireHolderAndTypeWhenLimited_doesNothingWhenUnlimited() {
        service.requireHolderAndTypeWhenLimited(null, null, 0);
    }

    @Test
    void requireHolderAndTypeWhenLimited_failsClosedWhenHolderIsMissing() {
        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.requireHolderAndTypeWhenLimited(null, "IdentityCredential", 1));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_FAIL_CLOSED, exception.getError());
        assertEquals(400, exception.getResponse().getStatus());
    }

    @Test
    void requireHolderAndTypeWhenLimited_failsClosedWhenTypeIsMissing() {
        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.requireHolderAndTypeWhenLimited("user-1", " ", 1));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
        assertEquals(400, exception.getResponse().getStatus());
    }

    @Test
    void enforceWithinReservationTransaction_doesNothingWhenUnlimited() {
        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 0, OVERFLOW_POLICY_REJECT, "current");

        verify(statusListRepository, never()).findMappingsByUser(any(), any(), any());
    }

    @Test
    void enforceWithinReservationTransaction_readsHolderMappingsOnce() {
        stubIssuedCredentials("issued-1");
        stubHolderMappings(successfulMapping("issued-1"), initMapping("sibling"));

        assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        2,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        verify(statusListRepository).findMappingsByUser(entityManager, "realm-1", "user-1");
        verifyNoMoreInteractions(statusListRepository);
    }

    @Test
    void enforceWithinReservationTransaction_rejectsWhenIssuedCredentialsReachMax() {
        stubIssuedCredentials("issued-1", "issued-2", "issued-3");
        stubHolderMappings(successfulMapping("issued-1"), successfulMapping("issued-2"), successfulMapping("issued-3"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        3,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_LIMIT_REACHED, exception.getError());
        assertEquals(409, exception.getResponse().getStatus());
    }

    @Test
    void enforceWithinReservationTransaction_ignoresOrphanMappingsWithoutIssuedCredential() {
        stubIssuedCredentials();
        stubHolderMappings(successfulMapping("orphan"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_allowsIssuanceBelowMax() {
        stubIssuedCredentials("issued-1", "issued-2");
        stubHolderMappings(successfulMapping("issued-1"), successfulMapping("issued-2"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 3, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_countsFailureMappingWhenIssuedCredentialExists() {
        stubIssuedCredentials("issued-1");
        stubHolderMappings(failureMapping("issued-1"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_ignoresFailureMappingWithoutIssuedCredential() {
        stubIssuedCredentials();
        stubHolderMappings(failureMapping("orphan"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_countsUnmappedIssuedCredentialTowardLimit() {
        IssuedVerifiableCredentialModel leftover = issuedModel("issued-ghost", "vc-ghost", 1L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 2L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1"))
                .thenReturn(Stream.of(leftover, current));
        stubHolderMappings();
        stubCredentialType("vc-ghost", "IdentityCredential");

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_ignoresConcurrentUnmappedIssuedCredential() {
        IssuedVerifiableCredentialModel sibling = issuedModel("sibling", "vc-sibling", 10L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 10L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(sibling, current));
        stubHolderMappings();
        stubCredentialType("vc-sibling", "IdentityCredential");

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_excludesCurrentTokenFromOccupancy() {
        stubIssuedCredentials("current");
        stubHolderMappings(successfulMapping("current"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_doesNotCountRevokedMapping() {
        stubIssuedCredentials("issued-1");
        stubHolderMappings(revokedMapping("issued-1"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_doesNotCountInitMappingTowardActiveCount() {
        stubIssuedCredentials("issued-init");
        stubHolderMappings(staleInitMapping("issued-init"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void enforceWithinReservationTransaction_countsInFlightInitTowardLimit() {
        stubIssuedCredentials();
        stubHolderMappings(initMapping("sibling"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_onlyCountsInitCreatedWithinInFlightWindow() {
        IssuedVerifiableCredentialModel leftover = issuedModel("issued-stale", "vc-stale", 1L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 2L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1"))
                .thenReturn(Stream.of(leftover, current));
        stubHolderMappings(staleInitMapping("issued-stale"));

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT, "current");
    }

    @Test
    void inFlightInitWindowMs_scalesWithIssuanceTimeoutAboveTheFloor() {
        assertEquals(
                CredentialIssuanceQuotaService.MIN_IN_FLIGHT_INIT_WINDOW_MS,
                CredentialIssuanceQuotaService.inFlightInitWindowMs(null));

        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ISSUANCE_TIMEOUT)).thenReturn("40000");
        assertEquals(120_000L, CredentialIssuanceQuotaService.inFlightInitWindowMs(realm));
    }

    @Test
    void enforceWithinReservationTransaction_countsInFlightInitFromEarlierIssuedSibling() {
        IssuedVerifiableCredentialModel sibling = issuedModel("sibling", "vc-sibling", 9L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 10L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(sibling, current));
        stubHolderMappings(initMapping("sibling"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_countsConcurrentInitTowardLimit() {
        IssuedVerifiableCredentialModel sibling = issuedModel("sibling", "vc-sibling", 10L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 10L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(sibling, current));
        stubHolderMappings(initMapping("sibling"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REJECT,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_revokesOldestWhenPolicyIsRevokeOldest() throws Exception {
        StatusListMappingEntity oldest = successfulMapping("token-oldest");
        oldest.setId("mapping-1");

        stubIssuedCredentials("token-oldest");
        stubHolderMappings(oldest);

        List<StatusListMappingEntity> pendingRemote = service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REVOKE_OLDEST, "current");

        assertEquals(List.of(oldest), pendingRemote);
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_revokesStableOldestWhenTimestampsTie() throws Exception {
        StatusListMappingEntity laterId = successfulMapping("token-z");
        laterId.setId("mapping-z");
        StatusListMappingEntity earlierId = successfulMapping("token-a");
        earlierId.setId("mapping-a");
        setCreatedTimestamp(laterId, 1_000L);
        setCreatedTimestamp(earlierId, 1_000L);

        stubIssuedCredentials("token-z", "token-a");
        stubHolderMappings(laterId, earlierId);

        List<StatusListMappingEntity> pendingRemote = service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 2, OVERFLOW_POLICY_REVOKE_OLDEST, "current");

        assertEquals(List.of(earlierId), pendingRemote);
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_selectsOldestOccupyingSuccessRegardlessOfNewerFailure() throws Exception {
        StatusListMappingEntity olderSuccess = successfulMapping("token-success");
        olderSuccess.setId("mapping-success");
        StatusListMappingEntity newerFailure = failureMapping("token-failure");
        newerFailure.setId("mapping-failure");
        setCreatedTimestamp(olderSuccess, 500L);
        setCreatedTimestamp(newerFailure, 1_000L);

        stubIssuedCredentials("token-success", "token-failure");
        stubHolderMappings(olderSuccess, newerFailure);

        List<StatusListMappingEntity> pendingRemote = service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 2, OVERFLOW_POLICY_REVOKE_OLDEST, "current");

        assertEquals(List.of(olderSuccess), pendingRemote);
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_revokesExcessOldestWhenHolderIsAboveMax() throws Exception {
        StatusListMappingEntity first = successfulMapping("token-1");
        first.setId("mapping-1");
        StatusListMappingEntity second = successfulMapping("token-2");
        second.setId("mapping-2");
        StatusListMappingEntity third = successfulMapping("token-3");
        third.setId("mapping-3");
        StatusListMappingEntity fourth = successfulMapping("token-4");
        fourth.setId("mapping-4");
        StatusListMappingEntity fifth = successfulMapping("token-5");
        fifth.setId("mapping-5");
        setCreatedTimestamp(first, 100L);
        setCreatedTimestamp(second, 200L);
        setCreatedTimestamp(third, 300L);
        setCreatedTimestamp(fourth, 400L);
        setCreatedTimestamp(fifth, 500L);

        stubIssuedCredentials("token-1", "token-2", "token-3", "token-4", "token-5");
        stubHolderMappings(first, second, third, fourth, fifth);

        // max lowered to 3 with 5 occupying SUCCESS rows: free 5 - 3 + 1 = 3 oldest.
        List<StatusListMappingEntity> pendingRemote = service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 3, OVERFLOW_POLICY_REVOKE_OLDEST, "current");

        assertEquals(List.of(first, second, third), pendingRemote);
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_failsWhenOldestOccupyingMappingIsFailure() throws Exception {
        StatusListMappingEntity olderFailure = failureMapping("token-failure");
        olderFailure.setId("mapping-failure");
        StatusListMappingEntity newerSuccess = successfulMapping("token-success");
        newerSuccess.setId("mapping-success");
        setCreatedTimestamp(olderFailure, 500L);
        setCreatedTimestamp(newerSuccess, 1_000L);

        stubIssuedCredentials("token-failure", "token-success");
        stubHolderMappings(olderFailure, newerSuccess);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        2,
                        OVERFLOW_POLICY_REVOKE_OLDEST,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        assertEquals(TokenStatus.VALID, olderFailure.getTokenStatus());
        assertEquals(TokenStatus.VALID, newerSuccess.getTokenStatus());
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_failsWhenOnlyFailureOccupiesSlot() throws Exception {
        StatusListMappingEntity failed = failureMapping("token-failed");
        failed.setId("mapping-failed");

        stubIssuedCredentials("token-failed");
        stubHolderMappings(failed);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REVOKE_OLDEST,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        assertEquals(TokenStatus.VALID, failed.getTokenStatus());
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_failsWhenOnlyUnmappedLeftoversRemain() {
        IssuedVerifiableCredentialModel leftover = issuedModel("issued-ghost", "vc-ghost", 1L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 2L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1"))
                .thenReturn(Stream.of(leftover, current));
        stubHolderMappings();
        stubCredentialType("vc-ghost", "IdentityCredential");

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REVOKE_OLDEST,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_failsWhenOldestOccupantIsUnmappedLeftover() throws Exception {
        IssuedVerifiableCredentialModel leftover = issuedModel("issued-ghost", "vc-ghost", 100L);
        IssuedVerifiableCredentialModel newer = issuedModel("token-success", null, 200L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 300L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1"))
                .thenReturn(Stream.of(leftover, newer, current));
        StatusListMappingEntity newerSuccess = successfulMapping("token-success");
        newerSuccess.setId("mapping-success");
        setCreatedTimestamp(newerSuccess, 200L);
        stubHolderMappings(newerSuccess);
        stubCredentialType("vc-ghost", "IdentityCredential");

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        2,
                        OVERFLOW_POLICY_REVOKE_OLDEST,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        assertEquals(TokenStatus.VALID, newerSuccess.getTokenStatus());
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_revokesOlderSuccessBeforeNewerUnmappedLeftover() throws Exception {
        IssuedVerifiableCredentialModel older = issuedModel("token-success", null, 100L);
        IssuedVerifiableCredentialModel leftover = issuedModel("issued-ghost", "vc-ghost", 200L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 300L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1"))
                .thenReturn(Stream.of(older, leftover, current));
        StatusListMappingEntity olderSuccess = successfulMapping("token-success");
        olderSuccess.setId("mapping-success");
        setCreatedTimestamp(olderSuccess, 100L);
        stubHolderMappings(olderSuccess);
        stubCredentialType("vc-ghost", "IdentityCredential");

        List<StatusListMappingEntity> pendingRemote = service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 2, OVERFLOW_POLICY_REVOKE_OLDEST, "current");

        assertEquals(List.of(olderSuccess), pendingRemote);
    }

    @Test
    void enforceWithinReservationTransaction_rejectsRevokeOldestWhenOnlyInFlightRemains() {
        IssuedVerifiableCredentialModel sibling = issuedModel("sibling", "vc-sibling", 10L);
        IssuedVerifiableCredentialModel current = issuedModel("current", "vc-current", 10L);
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(sibling, current));
        stubHolderMappings(initMapping("sibling"));

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager,
                        "realm-1",
                        "user-1",
                        "IdentityCredential",
                        1,
                        OVERFLOW_POLICY_REVOKE_OLDEST,
                        "current"));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void revokeOldestForOverflow_failsClosedWhenRevokeFails() throws Exception {
        StatusListMappingEntity oldest = successfulMapping("token-oldest");
        oldest.setId("mapping-1");

        doThrow(new StatusListException("status list unavailable"))
                .when(credentialRevocationService)
                .revokeMapping(oldest);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class, () -> service.revokeOldestForOverflow(List.of(oldest)));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_FAIL_CLOSED, exception.getError());
        assertEquals(400, exception.getResponse().getStatus());
        assertEquals(TokenStatus.VALID, oldest.getTokenStatus());
        verify(statusListRepository, never()).withEntityManagerInTransaction(any());
        verify(statusListRepository, never()).save(any());
    }

    @Test
    void revokeOldestForOverflow_keepsEarlierRevokesWhenALaterOneFails() throws Exception {
        StatusListMappingEntity first = successfulMapping("token-1");
        first.setId("mapping-1");
        StatusListMappingEntity second = successfulMapping("token-2");
        second.setId("mapping-2");
        StatusListMappingEntity third = successfulMapping("token-3");
        third.setId("mapping-3");

        lenient()
                .doThrow(new StatusListException("status list unavailable"))
                .when(credentialRevocationService)
                .revokeMapping(second);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.revokeOldestForOverflow(List.of(first, second, third)));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        verify(credentialRevocationService).revokeMapping(first);
        verify(credentialRevocationService).revokeMapping(second);
        verify(credentialRevocationService, never()).revokeMapping(third);
    }

    @Test
    void listLimits_returnsQuotaMetadataForConfiguredTypes() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", successfulMapping("issued-1"), "orphan", successfulMapping("orphan")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")));

        assertEquals(1, limits.size());
        IssuedCredentialLimit limit = limits.get(0);
        assertEquals("IdentityCredential", limit.credentialConfigurationId());
        assertEquals(2, limit.max());
        assertEquals(1L, limit.activeCount());
        assertEquals(1L, limit.remaining());
        assertEquals(OVERFLOW_POLICY_REJECT, limit.overflowPolicy());
    }

    @Test
    void listLimits_countsFailureMappingWhenIssuedCredentialExists() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", failureMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")));

        assertEquals(1, limits.size());
        assertEquals(1L, limits.get(0).activeCount());
        assertEquals(1L, limits.get(0).remaining());
    }

    @Test
    void listLimits_reflectsConfiguredRevokeOldestPolicy() {
        stubCredentialScope("IdentityCredential", "2", OVERFLOW_POLICY_REVOKE_OLDEST);
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", successfulMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")));

        assertEquals(1, limits.size());
        assertEquals(OVERFLOW_POLICY_REVOKE_OLDEST, limits.get(0).overflowPolicy());
        assertEquals(1L, limits.get(0).remaining());
    }

    @Test
    void listLimits_countsUnmappedIssuedCredentialTowardQuota() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of());
        stubCredentialType("vc-1", "IdentityCredential");

        List<IssuedCredentialLimit> limits =
                service.listLimits(realm, "user-1", List.of(issuedModel("issued-1", "vc-1")));

        assertEquals(1, limits.size());
        assertEquals(1L, limits.get(0).activeCount());
        assertEquals(1L, limits.get(0).remaining());
    }

    @Test
    void listLimits_doesNotCountRevokedMapping() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", revokedMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")));

        assertEquals(1, limits.size());
        assertEquals(0L, limits.get(0).activeCount());
        assertEquals(2L, limits.get(0).remaining());
    }

    @Test
    void occupiesQuota_matchesIssuanceOccupancyRule() {
        assertTrue(CredentialIssuanceQuotaService.occupiesQuota(null));
        assertTrue(CredentialIssuanceQuotaService.occupiesQuota(successfulMapping("issued-1")));
        assertTrue(CredentialIssuanceQuotaService.occupiesQuota(failureMapping("issued-1")));
        assertFalse(CredentialIssuanceQuotaService.occupiesQuota(initMapping("issued-1")));
        assertFalse(CredentialIssuanceQuotaService.occupiesQuota(revokedMapping("issued-1")));
        assertFalse(CredentialIssuanceQuotaService.occupiesQuota(legacyMapping("issued-1")));
    }

    @Test
    void listLimits_doesNotCountLegacyMappingWithoutCredentialType() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", legacyMapping("issued-1")));
        UserVerifiableCredentialModel verifiableCredential = mock(UserVerifiableCredentialModel.class);
        lenient().when(userProvider.getVerifiableCredentialById("vc-1")).thenReturn(verifiableCredential);
        lenient().when(verifiableCredential.getClientScopeId()).thenReturn("scope-1");
        lenient().when(realm.getClientScopeById("scope-1")).thenReturn(credentialScope);

        List<IssuedCredentialLimit> limits =
                service.listLimits(realm, "user-1", List.of(issuedModel("issued-1", "vc-1")));

        assertEquals(1, limits.size());
        assertEquals(0L, limits.get(0).activeCount());
        assertEquals(2L, limits.get(0).remaining());
    }

    @Test
    void listLimits_doesNotCountInitMapping() {
        stubCredentialScope("IdentityCredential", "2");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findMappingsByTokenIds(eq("realm-1"), eq("user-1"), any()))
                .thenReturn(Map.of("issued-1", initMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")));

        assertEquals(1, limits.size());
        assertEquals(0L, limits.get(0).activeCount());
        assertEquals(2L, limits.get(0).remaining());
    }

    @Test
    void listLimits_omitsUnlimitedTypes() {
        stubCredentialScope("IdentityCredential", "0");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));

        assertTrue(service.listLimits(realm, "user-1", List.of(issuedModel("issued-1")))
                .isEmpty());
    }

    private void stubIssuedCredentials(String... ids) {
        IssuedVerifiableCredentialModel[] credentials = new IssuedVerifiableCredentialModel[ids.length];
        for (int i = 0; i < ids.length; i++) {
            credentials[i] = issuedModel(ids[i]);
        }
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(credentials));
    }

    private void stubHolderMappings(StatusListMappingEntity... mappings) {
        when(statusListRepository.findMappingsByUser(entityManager, "realm-1", "user-1"))
                .thenReturn(List.of(mappings));
    }

    private void stubCredentialType(String verifiableCredentialId, String type) {
        UserVerifiableCredentialModel verifiableCredential = mock(UserVerifiableCredentialModel.class);
        when(userProvider.getVerifiableCredentialById(verifiableCredentialId)).thenReturn(verifiableCredential);
        when(verifiableCredential.getClientScopeId()).thenReturn("scope-1");
        when(realm.getClientScopeById("scope-1")).thenReturn(credentialScope);
        when(credentialScope.getProtocol()).thenReturn(OID4VCLoginProtocolFactory.PROTOCOL_ID);
        lenient()
                .when(credentialScope.getAttribute("vc.credential_configuration_id"))
                .thenReturn(type);
        lenient().when(credentialScope.getName()).thenReturn(type);
    }

    private static IssuedVerifiableCredentialModel issuedModel(String id) {
        return issuedModel(id, null);
    }

    private static IssuedVerifiableCredentialModel issuedModel(String id, String verifiableCredentialId) {
        return issuedModel(id, verifiableCredentialId, null);
    }

    private static IssuedVerifiableCredentialModel issuedModel(
            String id, String verifiableCredentialId, Long issuedAt) {
        IssuedVerifiableCredentialModel credential = new IssuedVerifiableCredentialModel();
        credential.setId(id);
        credential.setVerifiableCredentialId(verifiableCredentialId);
        credential.setIssuedAt(issuedAt);
        return credential;
    }

    private static StatusListMappingEntity successfulMapping(String tokenId) {
        return mapping(tokenId, StatusListMappingEntity.MappingStatus.SUCCESS);
    }

    private static StatusListMappingEntity failureMapping(String tokenId) {
        return mapping(tokenId, StatusListMappingEntity.MappingStatus.FAILURE);
    }

    private static StatusListMappingEntity initMapping(String tokenId) {
        return mapping(tokenId, StatusListMappingEntity.MappingStatus.INIT);
    }

    private static StatusListMappingEntity staleInitMapping(String tokenId) {
        int windowSeconds = (int) (CredentialIssuanceQuotaService.MIN_IN_FLIGHT_INIT_WINDOW_MS / 1000);
        Time.setOffset(-(windowSeconds + 1));
        try {
            return initMapping(tokenId);
        } finally {
            Time.setOffset(0);
        }
    }

    private static StatusListMappingEntity revokedMapping(String tokenId) {
        StatusListMappingEntity mapping = successfulMapping(tokenId);
        mapping.setTokenStatus(TokenStatus.INVALID);
        return mapping;
    }

    private static StatusListMappingEntity legacyMapping(String tokenId) {
        StatusListMappingEntity mapping = successfulMapping(tokenId);
        mapping.setCredentialConfigurationId(null);
        return mapping;
    }

    private static StatusListMappingEntity mapping(String tokenId, StatusListMappingEntity.MappingStatus status) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setTokenId(tokenId);
        mapping.setCredentialConfigurationId("IdentityCredential");
        mapping.setStatus(status);
        return mapping;
    }

    private void stubCredentialScope(String credentialConfigurationId, String max) {
        stubCredentialScope(credentialConfigurationId, max, null);
    }

    private void stubCredentialScope(String credentialConfigurationId, String max, String overflowPolicy) {
        when(credentialScope.getProtocol()).thenReturn(OID4VCLoginProtocolFactory.PROTOCOL_ID);
        when(credentialScope.getProtocolMappersStream()).thenAnswer(invocation -> Stream.of(mapperModel));
        when(mapperModel.getProtocolMapper()).thenReturn(StatusListProtocolMapper.Constants.MAPPER_ID);
        if (overflowPolicy == null) {
            when(mapperModel.getConfig())
                    .thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, max));
        } else {
            when(mapperModel.getConfig())
                    .thenReturn(Map.of(
                            StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER,
                            max,
                            StatusListConfig.STATUS_LIST_OVERFLOW_POLICY,
                            overflowPolicy));
        }
        lenient()
                .when(credentialScope.getAttribute("vc.credential_configuration_id"))
                .thenReturn(credentialConfigurationId);
        lenient().when(credentialScope.getName()).thenReturn(credentialConfigurationId);
    }

    private static void setCreatedTimestamp(StatusListMappingEntity mapping, long timestamp) {
        try {
            var field = StatusListMappingEntity.class.getDeclaredField("createdTimestamp");
            field.setAccessible(true);
            field.set(mapping, timestamp);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
