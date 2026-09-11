package io.github.adorsysgis.keycloakstatuslist.service;

import static io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.OVERFLOW_POLICY_REJECT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse.IssuedCredentialLimit;
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
    void enforceBeforeIssuance_doesNothingWhenUnlimited() {
        service.enforceBeforeIssuance("realm-1", "user-1", "IdentityCredential", 0);

        verify(statusListRepository, never())
                .countSuccessfulNonRevokedMappings("realm-1", "user-1", "IdentityCredential");
    }

    @Test
    void enforceBeforeIssuance_failsClosedWhenLimitIsSetAndHolderIsMissing() {
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> service.enforceBeforeIssuance("realm-1", null, "IdentityCredential", 1));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceBeforeIssuance_failsClosedWhenLimitIsSetAndTypeIsMissing() {
        RuntimeException exception =
                assertThrows(RuntimeException.class, () -> service.enforceBeforeIssuance("realm-1", "user-1", " ", 1));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceBeforeIssuance_rejectsWhenActiveCountReachesMax() {
        when(statusListRepository.countSuccessfulNonRevokedMappings("realm-1", "user-1", "IdentityCredential"))
                .thenReturn(3L);

        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> service.enforceBeforeIssuance("realm-1", "user-1", "IdentityCredential", 3));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
    }

    @Test
    void enforceBeforeIssuance_allowsIssuanceBelowMax() {
        when(statusListRepository.countSuccessfulNonRevokedMappings("realm-1", "user-1", "IdentityCredential"))
                .thenReturn(2L);

        service.enforceBeforeIssuance("realm-1", "user-1", "IdentityCredential", 3);
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
