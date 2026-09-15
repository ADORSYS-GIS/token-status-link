package io.github.adorsysgis.keycloakstatuslist;

import static io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListEndpointUriResolver;
import io.github.adorsysgis.keycloakstatuslist.exception.CredentialIssuanceQuotaException;
import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import io.github.adorsysgis.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import io.github.adorsysgis.keycloakstatuslist.jpa.repository.StatusListRepository;
import io.github.adorsysgis.keycloakstatuslist.model.Status;
import io.github.adorsysgis.keycloakstatuslist.model.StatusListClaim;
import io.github.adorsysgis.keycloakstatuslist.model.TokenStatus;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialIssuanceQuotaService;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.PersistenceException;
import jakarta.ws.rs.core.HttpHeaders;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IssuedVerifiableCredentialModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.ProtocolMapper;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

class StatusListProtocolMapperTest extends MockKeycloakTest {

    LogCaptor logCaptor = LogCaptor.forName("io.github.adorsysgis.keycloakstatuslist");

    protected static final String TEST_SERVER_URL = "https://example.com";
    protected static final String TEST_LIST_ID = "test-list-id";

    @Mock
    ProtocolMapperModel mapperModel;

    @Mock
    UserModel holder;

    @Mock
    StatusListService statusListService;

    @Mock
    HttpHeaders headers;

    StatusListProtocolMapper mapper;
    HashMap<String, Object> claims;
    StatusListRepository statusListRepository;

    @BeforeEach
    void setup() {
        mapper = spy(new StatusListProtocolMapper(session));
        setPrivateField(mapper, "mapperModel", mapperModel);
        setPrivateField(mapper, "statusListService", statusListService);

        // Initialize claims (credential payload)
        claims = new HashMap<>();
        claims.put(Constants.ID_CLAIM_KEY, "did:example:123456789");

        // Run mocks
        mockDefaultRealmConfig();
        mockStatusListRepository(0L);
        lenient().when(context.getRequestHeaders()).thenReturn(headers);
    }

    @Test
    void testDefaultConstructor() {
        new StatusListProtocolMapper();
    }

    @Test
    void shouldCreateSessionBoundMapperInstance() {
        ProtocolMapper created = mapper.create(session);
        assertInstanceOf(StatusListProtocolMapper.class, created);
    }

    @Test
    void shouldReturnWithoutMappingWhenSessionIsMissing() {
        StatusListProtocolMapper mapperWithoutSession = new StatusListProtocolMapper();
        HashMap<String, Object> localClaims = new HashMap<>();
        localClaims.put(Constants.ID_CLAIM_KEY, "did:example:123");

        mapperWithoutSession.setClaim(localClaims, userSession);

        assertThat(localClaims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
    }

    @Test
    void testGetMetadataAttributePath() {
        assertEquals(List.of("credentialSubject", Constants.STATUS_CLAIM_KEY), mapper.getMetadataAttributePath());
    }

    @Test
    void shouldExposeMapperMetadataMethods() {
        assertEquals(Constants.MAPPER_ID, mapper.getId());
        assertEquals("Status List Claim Mapper", mapper.getDisplayType());
        assertTrue(mapper.getHelpText().contains("status list claim"));
        assertFalse(mapper.includeInMetadata());
        assertEquals(2, mapper.getIndividualConfigProperties().size());
        assertEquals(
                StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER,
                mapper.getIndividualConfigProperties().get(0).getName());
        assertEquals(
                CredentialIssuanceQuotaService.OVERFLOW_POLICY_CONFIG,
                mapper.getIndividualConfigProperties().get(1).getName());
        mapper.close();
    }

    @Test
    void shouldNoOpForW3CVerifiableCredentialClaimSetter() {
        mapper.setClaim((org.keycloak.protocol.oid4vc.model.VerifiableCredential) null, userSession);
    }

    @Test
    void shouldMapSuccessfully_WhenStatusIsSent() throws Exception {
        long idx = mockGetNextIndex();

        // Act
        mapper.setClaim(claims, userSession);

        // Assertions
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, listUri(TEST_LIST_ID))));
        assertEquals(idx, status.getStatusList().getIdx());

        // 2. Verify service was called with correct payload
        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).publishOrUpdate(payloadCaptor.capture());
        StatusListService.StatusListPayload capturedPayload = payloadCaptor.getValue();
        assertThat(capturedPayload.listId(), equalTo(TEST_LIST_ID));
        assertThat(capturedPayload.status().size(), equalTo(1));
        assertThat(capturedPayload.status().get(0).index(), equalTo(idx));
        assertThat(capturedPayload.status().get(0).status(), equalTo(TokenStatus.VALID));

        // 3. Verify DB persist was called
        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        StatusListMappingEntity capturedEntity = entityCaptor.getValue();
        assertEquals(idx, capturedEntity.getIdx());
        assertEquals(TEST_REALM_ID, capturedEntity.getRealmId());
        assertEquals("did:example:123456789", capturedEntity.getTokenId());
        assertEquals(MappingStatus.SUCCESS, capturedEntity.getStatus());
        verify(statusListRepository).save(capturedEntity);
    }

    @Test
    void shouldUseIssuedCredentialIdFromAuthenticatedAccessTokenAsMappingKey() {
        mockGetNextIndex();
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        mapper.setClaim(claims, userSession);

        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        assertEquals("issued-credential-1", entityCaptor.getValue().getTokenId());
        assertEquals("PidCredential", entityCaptor.getValue().getCredentialConfigurationId());
    }

    @Test
    void shouldUseIssuedCredentialIdFromDpopAccessTokenAsMappingKey() {
        mockGetNextIndex();
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("DPoP " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        mapper.setClaim(claims, userSession);

        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        assertEquals("issued-credential-1", entityCaptor.getValue().getTokenId());
    }

    @Test
    void shouldMapSuccessfully_WhenSwitchingToNewList() {
        // Force running status list to be at max capacity to trigger creation of new list ID
        mockStatusListRepository(StatusListConfig.DEFAULT_MAX_ENTRIES);
        mockGetNextIndex();

        // Act
        mapper.setClaim(claims, userSession);

        // Assertions
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertThat(
                logCaptor.getDebugLogs(),
                hasItem(containsString(String.format(
                        "Running status list has reached max entries (%d), generating new list ID",
                        StatusListConfig.DEFAULT_MAX_ENTRIES))));
    }

    @Test
    void shouldNotMap_IfFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("false");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString("Status list is disabled")));
    }

    @Test
    void shouldDefaultToDisabledAndNullServerUrl_WhenRealmAttributesAreAbsent() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn(null);
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(null);

        StatusListConfig config = new StatusListConfig(realm);

        assertFalse(config.isEnabled());
        assertNull(config.getServerUrl());
    }

    @Test
    void shouldNotContactStatusListServer_WhenEnabledAttributeIsAbsent() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn(null);

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        verifyNoInteractions(statusListService);
    }

    @Test
    void shouldNotContactStatusListServer_WhenServerUrlAttributeIsAbsent() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(null);

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
        verifyNoInteractions(statusListService);
    }

    @Test
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn("invalid-url");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndStatusServerUrlIsInvalid() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(" ");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(
                logCaptor.getErrorLogs(),
                hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldMap_WhenHttpStatusServerUrlIsUsed() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn("http://example.com");
        long idx = mockGetNextIndex();

        mapper.setClaim(claims, userSession);

        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertEquals(idx, status.getStatusList().getIdx());
        assertTrue(status.getStatusList().getUri().toString().startsWith("http://"));
    }

    @Test
    void shouldNotMap_IfDbPersistenceFails() {
        mockGetNextIndex();
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to initiate index mapping")));
    }

    @Test
    void shouldNotMap_IfDbCompletionFailsAfterPublishingStatus() {
        mockGetNextIndex();
        doThrow(new PersistenceException("DB Error")).when(statusListRepository).save(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to persist completion mapping status")));
    }

    @Test
    void shouldNotMap_WhenSendingStatusFails() throws Exception {
        mockGetNextIndex();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn("false");
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService)
                .publishOrUpdate(any(StatusListService.StatusListPayload.class));

        // Act
        mapper.setClaim(claims, userSession);

        // Assert
        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItems(containsString("Failed to send token status")));
        assertThat(logCaptor.getDebugLogs(), hasItems(containsString("Persisting completion mapping status: FAILURE")));
        assertThat(
                logCaptor.getWarnLogs(),
                hasItem(containsString("Status list publication failed; proceeding without status claim")));

        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(statusListRepository).save(entityCaptor.capture());
        assertEquals(MappingStatus.FAILURE, entityCaptor.getValue().getStatus());
    }

    @Test
    void shouldContinueIssuance_WhenOptionalAndDbPersistenceFails() {
        mockGetNextIndex();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn("false");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(
                logCaptor.getWarnLogs(),
                hasItem(containsString("Status list publication failed; proceeding without status claim")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndDbPersistenceFails() {
        mockGetNextIndex();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn("true");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(
                logCaptor.getErrorLogs(),
                hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndSendingStatusFails() throws Exception {
        mockGetNextIndex();
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn("true");
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService)
                .publishOrUpdate(any(StatusListService.StatusListPayload.class));

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(
                logCaptor.getErrorLogs(),
                hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldMapStatusEvenWhenIdClaimIsNotString() {
        mockGetNextIndex();
        claims.put(Constants.ID_CLAIM_KEY, 1234L);

        mapper.setClaim(claims, userSession);

        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
    }

    @Test
    void shouldMapStatusEvenWhenIdClaimIsMissing() {
        mockGetNextIndex();
        claims.remove(Constants.ID_CLAIM_KEY);

        mapper.setClaim(claims, userSession);

        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
    }

    @Test
    void shouldRejectIssuance_WhenHolderIsAtConfiguredMax() {
        mockGetNextIndex();
        stubHolder("holder-1");
        stubMapperMax("1");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));
        lenient()
                .doReturn(1L)
                .when(statusListRepository)
                .countInFlightMappings(any(), eq(TEST_REALM_ID), eq("holder-1"), eq("PidCredential"));

        CredentialIssuanceQuotaException exception =
                assertThrows(CredentialIssuanceQuotaException.class, () -> mapper.setClaim(claims, userSession));

        assertEquals(CredentialIssuanceQuotaService.LIMIT_REACHED_MESSAGE, exception.getMessage());
        assertEquals(409, exception.getResponse().getStatus());
        verify(entityManager, never()).persist(any());
        assertThat(claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
    }

    @Test
    void shouldFailClosed_WhenLimitIsConfiguredAndHolderCannotBeResolved() {
        mockGetNextIndex();
        stubMapperMax("1");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        CredentialIssuanceQuotaException exception =
                assertThrows(CredentialIssuanceQuotaException.class, () -> mapper.setClaim(claims, userSession));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
        assertEquals(400, exception.getResponse().getStatus());
        verify(entityManager, never()).persist(any());
    }

    @Test
    void shouldFailClosed_WhenLimitIsConfiguredAndCredentialTypeCannotBeResolved() {
        mockGetNextIndex();
        stubHolder("holder-1");
        stubMapperMax("1");

        CredentialIssuanceQuotaException exception =
                assertThrows(CredentialIssuanceQuotaException.class, () -> mapper.setClaim(claims, userSession));

        assertEquals(CredentialIssuanceQuotaService.FAIL_CLOSED_MESSAGE, exception.getMessage());
        assertEquals(400, exception.getResponse().getStatus());
        verify(entityManager, never()).persist(any());
    }

    @Test
    void shouldFailClosed_WhenLimitConfigurationIsInvalid() {
        mockGetNextIndex();
        stubHolder("holder-1");
        stubMapperMax("abc");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> mapper.setClaim(claims, userSession));

        assertTrue(exception.getMessage().contains("status-list-max-credentials-per-user"));
        verify(entityManager, never()).persist(any());
    }

    @Test
    void shouldAllowIssuance_WhenHolderIsBelowConfiguredMax() {
        mockGetNextIndex();
        stubHolder("holder-1");
        stubMapperMax("2");
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-1"));
        lenient()
                .doReturn(1L)
                .when(statusListRepository)
                .countInFlightMappings(any(), eq(TEST_REALM_ID), eq("holder-1"), eq("PidCredential"));

        mapper.setClaim(claims, userSession);

        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        assertEquals("holder-1", entityCaptor.getValue().getUserId());
        assertEquals("PidCredential", entityCaptor.getValue().getCredentialConfigurationId());
    }

    @Test
    void shouldRevokeOldestAndContinue_WhenOverflowPolicyIsRevokeOldest() throws Exception {
        mockGetNextIndex();
        stubHolder("holder-1");
        stubMapperConfig("1", CredentialIssuanceQuotaService.OVERFLOW_POLICY_REVOKE_OLDEST);
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer " + accessTokenWithIssuedCredentialId("issued-credential-2"));

        StatusListMappingEntity oldest = new StatusListMappingEntity();
        oldest.setId("oldest-mapping");
        oldest.setIdx(7L);
        oldest.setStatusListId(TEST_LIST_ID);
        oldest.setTokenId("issued-credential-1");
        oldest.setTokenStatus(TokenStatus.VALID);
        oldest.setStatus(MappingStatus.SUCCESS);
        oldest.setCredentialConfigurationId("PidCredential");

        UserProvider users = mock(UserProvider.class);
        IssuedVerifiableCredentialModel issued = new IssuedVerifiableCredentialModel();
        issued.setId("issued-credential-1");
        lenient().when(session.users()).thenReturn(users);
        lenient()
                .when(users.getIssuedVerifiableCredentialsStreamByUser("holder-1"))
                .thenReturn(Stream.of(issued));
        lenient()
                .doReturn(List.of(oldest))
                .when(statusListRepository)
                .findNonRevokedMappings(any(), eq(TEST_REALM_ID), eq("holder-1"), eq("PidCredential"));
        lenient()
                .doReturn(0L)
                .when(statusListRepository)
                .countInFlightMappings(any(), eq(TEST_REALM_ID), eq("holder-1"), eq("PidCredential"));

        mapper.setClaim(claims, userSession);

        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        verify(statusListService).updateStatusList(any(StatusListService.StatusListPayload.class), anyString());
        assertEquals(TokenStatus.INVALID, oldest.getTokenStatus());
        verify(statusListRepository).save(oldest);
    }

    private void mockDefaultRealmConfig() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn(TEST_SERVER_URL);
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MANDATORY));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_ENTRIES))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MAX_ENTRIES));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER))
                .thenReturn(null);
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_OVERFLOW_POLICY))
                .thenReturn(null);
    }

    private void mockStatusListRepository(long maxIdx) {
        statusListRepository = spy(new StatusListRepository(session));
        setPrivateField(statusListRepository, "session", session);
        setPrivateField(mapper, "statusListRepository", statusListRepository);

        var mapping = new StatusListMappingEntity();
        mapping.setStatusListId(TEST_LIST_ID);
        mapping.setIdx(maxIdx);

        lenient().doReturn(mapping).when(statusListRepository).lockLatestMapping(any(), anyString());
        lenient()
                .doAnswer(invocation -> invocation.getArgument(0))
                .when(statusListRepository)
                .save(any());
        lenient()
                .doReturn(List.of())
                .when(statusListRepository)
                .findNonRevokedMappings(any(), anyString(), any(), any());
        lenient()
                .doReturn(0L)
                .when(statusListRepository)
                .countInFlightMappings(any(), anyString(), anyString(), anyString());
        setPrivateField(
                mapper,
                "credentialIssuanceQuotaService",
                new CredentialIssuanceQuotaService(
                        session,
                        statusListRepository,
                        new CredentialRevocationService(session, statusListService, statusListRepository)));
    }

    private void stubHolder(String userId) {
        lenient().when(userSession.getUser()).thenReturn(holder);
        lenient().when(holder.getId()).thenReturn(userId);
    }

    private void stubMapperMax(String max) {
        stubMapperConfig(max, null);
    }

    private void stubMapperConfig(String max, String overflowPolicy) {
        if (overflowPolicy == null) {
            lenient()
                    .when(mapperModel.getConfig())
                    .thenReturn(Map.of(StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER, max));
            return;
        }

        lenient()
                .when(mapperModel.getConfig())
                .thenReturn(Map.of(
                        StatusListConfig.STATUS_LIST_MAX_CREDENTIALS_PER_USER,
                        max,
                        StatusListConfig.STATUS_LIST_OVERFLOW_POLICY,
                        overflowPolicy));
    }

    private long mockGetNextIndex() {
        long nextIndex = ThreadLocalRandom.current().nextLong(StatusListConfig.DEFAULT_MAX_ENTRIES - 1);

        lenient().doReturn(nextIndex).when(statusListRepository).getNextIndex(any(), anyString());

        return nextIndex;
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        StatusListEndpointUriResolver resolver = new StatusListEndpointUriResolver(TEST_SERVER_URL);
        return URI.create(resolver.statusListUrl(listId));
    }

    private String accessTokenWithIssuedCredentialId(String issuedCredentialId) {
        String issuedCredentialClaim =
                issuedCredentialId == null ? "" : ",\"issued_credential_id\":\"" + issuedCredentialId + "\"";
        String payload = """
                {
                  "typ": "Bearer",
                  "authorization_details": [
                    {
                      "type": "%s",
                      "credential_configuration_id": "PidCredential"%s
                    }
                  ]
                }
                """.formatted(OPENID_CREDENTIAL, issuedCredentialClaim);

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".";
    }
}
