package com.adorsys.keycloakstatuslist;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.PersistenceException;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.ProtocolMapper;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

class StatusListProtocolMapperTest extends MockKeycloakTest {

    LogCaptor logCaptor = LogCaptor.forName("com.adorsys.keycloakstatuslist");

    protected static final String TEST_SERVER_URL = "https://example.com";
    protected static final String TEST_LIST_ID = "test-list-id";

    @Mock
    ProtocolMapperModel mapperModel;

    @Mock
    StatusListService statusListService;

    StatusListProtocolMapper mapper;
    HashMap<String, Object> claims;
    StatusListRepository statusListRepository;
    HashMap<String, String> mapperConfig;

    @BeforeEach
    void setup() {
        mapperConfig = new HashMap<>();
        lenient().when(mapperModel.getConfig()).thenReturn(mapperConfig);

        mapper = spy(new StatusListProtocolMapper(session));
        setPrivateField(mapper, "mapperModel", mapperModel);
        setPrivateField(mapper, "statusListService", statusListService);

        // Initialize claims (credential payload)
        claims = new HashMap<>();
        claims.put(Constants.ID_CLAIM_KEY, "did:example:123456789");

        // Run mocks
        mockDefaultRealmConfig();
        mockStatusListRepository(0L);
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
        assertFalse(mapper.getIndividualConfigProperties().isEmpty());
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
        assertThat(capturedPayload.status().get(0).status(), equalTo(TokenStatus.VALID.getValue()));

        // 3. Verify DB persist was called
        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        StatusListMappingEntity capturedEntity = entityCaptor.getValue();
        assertEquals(idx, capturedEntity.getIdx());
        assertEquals(TEST_REALM_ID, capturedEntity.getRealmId());
        assertEquals(MappingStatus.SUCCESS, capturedEntity.getStatus());
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
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn("invalid-url");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
    }

    @Test
    void shouldNotMap_IfStatusServerUrlIsBlank() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(" ");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
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
    void shouldStillMap_IfDbPersistenceFailsAfterPublishingStatus() {
        mockGetNextIndex();
        doThrow(new PersistenceException("DB Error")).when(entityManager).merge(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should be mapped regardless", claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to persist completion mapping status")));
    }

    @Test
    void shouldNotMap_WhenSendingStatusFails() throws Exception {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
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
    }

    @Test
    void shouldContinueIssuance_WhenOptionalAndDbPersistenceFails() {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
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
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(
                logCaptor.getErrorLogs(),
                hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndSendingStatusFails() throws Exception {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
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

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", " , "})
    void shouldReturnNullMetadata_WhenNoClaimPathsConfigured(String configValue) {
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, configValue);

        String metadata = mapper.extractMetadata(claims);

        assertEquals(null, metadata);
    }

    @Test
    void shouldExtractTopLevelClaimAsMetadata() throws JsonProcessingException {
        claims.put("vct", "IdentityCredential");
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "vct");

        String metadata = mapper.extractMetadata(claims);

        Map<?, ?> parsed = new ObjectMapper().readValue(metadata, Map.class);
        assertEquals("IdentityCredential", parsed.get("vct"));
        assertEquals(1, parsed.size());
    }

    @Test
    void shouldExtractNestedClaimAsMetadata() throws JsonProcessingException {
        claims.put("sub", Map.of("email", "user@example.com", "name", "Jane"));
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "sub.email");

        String metadata = mapper.extractMetadata(claims);

        Map<?, ?> parsed = new ObjectMapper().readValue(metadata, Map.class);
        assertEquals("user@example.com", parsed.get("sub.email"));
        assertEquals(1, parsed.size());
    }

    @Test
    void shouldExtractMultipleClaimPathsAsMetadata() throws JsonProcessingException {
        claims.put("vct", "IdentityCredential");
        claims.put("sub", Map.of("email", "user@example.com"));
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "vct, sub.email");

        String metadata = mapper.extractMetadata(claims);

        Map<?, ?> parsed = new ObjectMapper().readValue(metadata, Map.class);
        assertEquals("IdentityCredential", parsed.get("vct"));
        assertEquals("user@example.com", parsed.get("sub.email"));
        assertEquals(2, parsed.size());
    }

    @Test
    void shouldSkipMissingClaimPaths() throws JsonProcessingException {
        claims.put("vct", "IdentityCredential");
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "vct, nonexistent");

        String metadata = mapper.extractMetadata(claims);

        Map<?, ?> parsed = new ObjectMapper().readValue(metadata, Map.class);
        assertEquals("IdentityCredential", parsed.get("vct"));
        assertEquals(1, parsed.size());
    }

    @Test
    void shouldReturnNullMetadata_WhenAllClaimPathsMissing() {
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "nonexistent, also.missing");

        String metadata = mapper.extractMetadata(claims);

        assertEquals(null, metadata);
    }

    @Test
    void shouldStoreMetadataInEntity_WhenClaimPathsConfigured() {
        claims.put("vct", "IdentityCredential");
        mapperConfig.put(Constants.METADATA_CLAIM_PATHS_KEY, "vct");
        mockGetNextIndex();

        mapper.setClaim(claims, userSession);

        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        StatusListMappingEntity capturedEntity = entityCaptor.getValue();
        assertThat(capturedEntity.getMetadata(), containsString("IdentityCredential"));
    }

    @Test
    void shouldResolveClaimPath_WhenPathPointsToMapValue() {
        Map<String, Object> nested = Map.of("level2", Map.of("level3", "deepValue"));
        Map<String, Object> testClaims = Map.of("level1", nested);

        Object result = StatusListProtocolMapper.resolveClaimPath(testClaims, "level1.level2.level3");

        assertEquals("deepValue", result);
    }

    @Test
    void shouldReturnNull_WhenPathTraversesNonMapValue() {
        Map<String, Object> testClaims = Map.of("key", "stringValue");

        Object result = StatusListProtocolMapper.resolveClaimPath(testClaims, "key.sub");

        assertEquals(null, result);
    }

    private void mockDefaultRealmConfig() {
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_ENABLED));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn(TEST_SERVER_URL);
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MANDATORY));
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_ENTRIES))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MAX_ENTRIES));
    }

    private void mockStatusListRepository(long maxIdx) {
        statusListRepository = spy(new StatusListRepository(session));
        setPrivateField(statusListRepository, "session", session);
        setPrivateField(mapper, "statusListRepository", statusListRepository);

        var mapping = new StatusListMappingEntity();
        mapping.setStatusListId(TEST_LIST_ID);
        mapping.setIdx(maxIdx);

        lenient().doReturn(mapping).when(statusListRepository).getLatestMapping(anyString());
    }

    private long mockGetNextIndex() {
        long nextIndex = ThreadLocalRandom.current().nextLong(StatusListConfig.DEFAULT_MAX_ENTRIES - 1);

        lenient().doReturn(nextIndex).when(statusListRepository).getNextIndex(any(), anyString());

        return nextIndex;
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        return UriBuilder.fromUri(TEST_SERVER_URL)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
    }
}
