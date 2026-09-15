package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
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
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceQuotaServiceTest {

    @Mock
    private StatusListRepository statusListRepository;

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
        service = new CredentialIssuanceQuotaService(statusListRepository);
        lenient().when(realm.getId()).thenReturn("realm-1");
    }

    @Test
    void resolveMax_returnsUnlimitedWhenNothingIsConfigured() {
        assertEquals(0, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_usesMapperConfigOverRealmFallback() {
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, "2"));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("9");

        assertEquals(2, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_mapperZeroMeansUnlimitedEvenIfRealmHasAFallback() {
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, "0"));
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
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, "  "));
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn("3");

        assertEquals(3, service.resolveMax(mapperModel, realm));
    }

    @Test
    void resolveMax_rejectsInvalidMapperConfig() {
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, "abc"));

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> service.resolveMax(mapperModel, realm));

        assertTrue(exception.getMessage().contains("abc"));
    }

    @Test
    void resolveMax_rejectsNegativeMapperConfig() {
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, "-1"));

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
        service.enforceWithinReservationTransaction(entityManager, "realm-1", "user-1", "IdentityCredential", 0);

        verify(statusListRepository, never()).acquireQuotaLock(any(), any(), any(), any());
        verify(statusListRepository, never()).countOccupyingMappings(any(), any(), any(), any());
    }

    @Test
    void enforceWithinReservationTransaction_rejectsWhenOccupyingCountReachesMax() {
        when(statusListRepository.countOccupyingMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(3L);

        CredentialIssuanceQuotaException exception = assertThrows(
                CredentialIssuanceQuotaException.class,
                () -> service.enforceWithinReservationTransaction(
                        entityManager, "realm-1", "user-1", "IdentityCredential", 3));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
        assertEquals(CredentialIssuanceQuotaException.ERROR_LIMIT_REACHED, exception.getError());
        assertEquals(409, exception.getResponse().getStatus());
        verify(statusListRepository).acquireQuotaLock(entityManager, "realm-1", "user-1", "IdentityCredential");
    }

    @Test
    void enforceWithinReservationTransaction_allowsIssuanceBelowMax() {
        when(statusListRepository.countOccupyingMappings(entityManager, "realm-1", "user-1", "IdentityCredential"))
                .thenReturn(2L);

        service.enforceWithinReservationTransaction(entityManager, "realm-1", "user-1", "IdentityCredential", 3);

        verify(statusListRepository)
                .acquireQuotaLock(eq(entityManager), eq("realm-1"), eq("user-1"), eq("IdentityCredential"));
    }

    @Test
    void ensureQuotaLockExists_skipsWhenUnlimited() {
        service.ensureQuotaLockExists("realm-1", "user-1", "IdentityCredential", 0);

        verify(statusListRepository, never()).ensureQuotaLockExists(any(), any(), any());
    }

    @Test
    void ensureQuotaLockExists_delegatesWhenLimited() {
        service.ensureQuotaLockExists("realm-1", "user-1", "IdentityCredential", 1);

        verify(statusListRepository).ensureQuotaLockExists("realm-1", "user-1", "IdentityCredential");
    }

    @Test
    void listLimits_returnsQuotaMetadataForConfiguredTypes() {
        stubCredentialScope("IdentityCredential", "1");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));
        when(statusListRepository.countSuccessfulNonRevokedMappingsByType("realm-1", "user-1"))
                .thenReturn(Map.of("IdentityCredential", 1L));

        List<IssuedCredentialLimit> limits = service.listLimits(realm, "user-1");

        assertEquals(1, limits.size());
        IssuedCredentialLimit limit = limits.get(0);
        assertEquals("IdentityCredential", limit.credentialConfigurationId());
        assertEquals(1, limit.max());
        assertEquals(1L, limit.activeCount());
        assertEquals(0L, limit.remaining());
        assertEquals(OVERFLOW_POLICY_REJECT, limit.overflowPolicy());
    }

    @Test
    void listLimits_omitsUnlimitedTypes() {
        stubCredentialScope("IdentityCredential", "0");
        when(realm.getClientScopesStream()).thenAnswer(invocation -> Stream.of(credentialScope));

        assertTrue(service.listLimits(realm, "user-1").isEmpty());
    }

    private void stubCredentialScope(String credentialConfigurationId, String max) {
        when(credentialScope.getProtocol()).thenReturn(OID4VCLoginProtocolFactory.PROTOCOL_ID);
        when(credentialScope.getProtocolMappersStream()).thenAnswer(invocation -> Stream.of(mapperModel));
        when(mapperModel.getProtocolMapper()).thenReturn(StatusListProtocolMapper.Constants.MAPPER_ID);
        when(mapperModel.getConfig())
                .thenReturn(Map.of(CredentialIssuanceQuotaService.MAX_CREDENTIALS_PER_USER_CONFIG, max));
        lenient()
                .when(credentialScope.getAttribute("vc.credential_configuration_id"))
                .thenReturn(credentialConfigurationId);
        lenient().when(credentialScope.getName()).thenReturn(credentialConfigurationId);
    }
}
