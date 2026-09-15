package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.service.CredentialIssuanceQuotaService.OVERFLOW_POLICY_REJECT;
import static io.github.adorsysgis.keycloakstatuslist.service.CredentialIssuanceQuotaService.OVERFLOW_POLICY_REVOKE_OLDEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
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

    private CredentialIssuanceQuotaService service;

    @BeforeEach
    void setUp() {
        service = new CredentialIssuanceQuotaService(session, statusListRepository, credentialRevocationService);
        lenient().when(realm.getId()).thenReturn("realm-1");
        lenient().when(session.users()).thenReturn(userProvider);
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
                .thenReturn(Map.of(CredentialIssuanceQuotaService.OVERFLOW_POLICY_CONFIG, OVERFLOW_POLICY_REVOKE_OLDEST));
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
                entityManager, "realm-1", "user-1", "IdentityCredential", 0, OVERFLOW_POLICY_REJECT);

        verify(statusListRepository, never()).countInFlightMappings(any(), any(), any(), any());
        verify(statusListRepository, never()).findNonRevokedMappings(any(), any(), any(), any());
    }

    @Test
    void enforceWithinReservationTransaction_rejectsWhenIssuedCredentialsReachMax() throws Exception {
        stubIssuedCredentials("issued-1", "issued-2", "issued-3");
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(
                        successfulMapping("issued-1"), successfulMapping("issued-2"), successfulMapping("issued-3")));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager, "realm-1", "user-1", "IdentityCredential", 3, OVERFLOW_POLICY_REJECT));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_LIMIT_REACHED, exception.getError());
        assertEquals(409, exception.getResponse().getStatus());
        verify(credentialRevocationService, never()).revokeMapping(any());
    }

    @Test
    void enforceWithinReservationTransaction_ignoresOrphanMappingsWithoutIssuedCredential() {
        stubIssuedCredentials();
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(successfulMapping("orphan")));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT);
    }

    @Test
    void enforceWithinReservationTransaction_allowsIssuanceBelowMax() {
        stubIssuedCredentials("issued-1", "issued-2");
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(successfulMapping("issued-1"), successfulMapping("issued-2")));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 3, OVERFLOW_POLICY_REJECT);
    }

    @Test
    void enforceWithinReservationTransaction_countsFailureMappingWhenIssuedCredentialExists() {
        stubIssuedCredentials("issued-1");
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(failureMapping("issued-1")));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_ignoresFailureMappingWithoutIssuedCredential() {
        stubIssuedCredentials();
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(failureMapping("orphan")));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT);
    }

    @Test
    void enforceWithinReservationTransaction_countsInFlightInitTowardLimit() {
        stubIssuedCredentials();
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of());
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(1L);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REJECT));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceWithinReservationTransaction_revokesOldestWhenPolicyIsRevokeOldest() throws Exception {
        StatusListMappingEntity oldest = successfulMapping("token-oldest");
        oldest.setId("mapping-1");

        stubIssuedCredentials("token-oldest");
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(oldest));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);

        service.enforceWithinReservationTransaction(
                entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REVOKE_OLDEST);

        verify(credentialRevocationService).revokeMapping(oldest);
    }

    @Test
    void enforceWithinReservationTransaction_failsWhenRevokeOldestCannotRevoke() throws Exception {
        StatusListMappingEntity oldest = successfulMapping("token-oldest");
        oldest.setId("mapping-1");

        stubIssuedCredentials("token-oldest");
        when(statusListRepository.findNonRevokedMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(List.of(oldest));
        when(statusListRepository.countInFlightMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(0L);
        doThrow(new StatusListException("status list unavailable"))
                .when(credentialRevocationService)
                .revokeMapping(oldest);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager, "realm-1", "user-1", "IdentityCredential", 1, OVERFLOW_POLICY_REVOKE_OLDEST));

        assertEquals(CredentialIssuanceQuotaService.REVOKE_OLDEST_FAILED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_FAIL_CLOSED, exception.getError());
        assertEquals(400, exception.getResponse().getStatus());
    }

    @Test
    void listLimits_returnsQuotaMetadataForConfiguredTypes() {
        stubCredentialScope("IdentityCredential", "2", null);
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findNonRevokedMappings("realm-1", "user-1"))
                .thenReturn(List.of(successfulMapping("issued-1"), successfulMapping("orphan")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of("issued-1"));

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
        stubCredentialScope("IdentityCredential", "2", null);
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findNonRevokedMappings("realm-1", "user-1"))
                .thenReturn(List.of(failureMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of("issued-1"));

        assertEquals(1, limits.size());
        assertEquals(1L, limits.get(0).activeCount());
        assertEquals(1L, limits.get(0).remaining());
    }

    @Test
    void listLimits_reflectsConfiguredRevokeOldestPolicy() {
        stubCredentialScope("IdentityCredential", "2", OVERFLOW_POLICY_REVOKE_OLDEST);
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.findNonRevokedMappings("realm-1", "user-1"))
                .thenReturn(List.of(successfulMapping("issued-1")));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1", List.of("issued-1"));

        assertEquals(1, limits.size());
        assertEquals(OVERFLOW_POLICY_REVOKE_OLDEST, limits.get(0).overflowPolicy());
        assertEquals(1L, limits.get(0).remaining());
    }

    @Test
    void listLimits_omitsUnlimitedTypes() {
        stubCredentialScope("IdentityCredential", "0", null);
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));

        assertTrue(service.listLimits(realm, "user-1", List.of("issued-1")).isEmpty());
    }

    private void stubIssuedCredentials(String... ids) {
        IssuedVerifiableCredentialModel[] credentials = new IssuedVerifiableCredentialModel[ids.length];
        for (int i = 0; i < ids.length; i++) {
            credentials[i] = new IssuedVerifiableCredentialModel();
            credentials[i].setId(ids[i]);
        }
        when(userProvider.getIssuedVerifiableCredentialsStreamByUser("user-1")).thenReturn(Stream.of(credentials));
    }

    private static StatusListMappingEntity successfulMapping(String tokenId) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setTokenId(tokenId);
        mapping.setCredentialConfigurationId("IdentityCredential");
        mapping.setStatus(StatusListMappingEntity.MappingStatus.SUCCESS);
        return mapping;
    }

    private static StatusListMappingEntity failureMapping(String tokenId) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setTokenId(tokenId);
        mapping.setCredentialConfigurationId("IdentityCredential");
        mapping.setStatus(StatusListMappingEntity.MappingStatus.FAILURE);
        return mapping;
    }

    private void stubCredentialScope(String credentialConfigurationId, String max, String overflowPolicy) {
        when(credentialScope.getProtocol()).thenReturn(OID4VCLoginProtocolFactory.PROTOCOL_ID);
        when(credentialScope.getProtocolMappersStream()).thenAnswer(invocation -> Stream.of(mapperModel));
        when(mapperModel.getProtocolMapper()).thenReturn(StatusListProtocolMapper.Constants.MAPPER_ID);
        if (overflowPolicy == null) {
            when(mapperModel.getConfig()).thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, max));
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
}
