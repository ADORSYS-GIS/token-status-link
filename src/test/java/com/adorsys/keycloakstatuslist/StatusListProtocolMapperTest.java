package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.PersistenceException;
import jakarta.ws.rs.core.UriBuilder;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import java.net.URI;
import java.util.HashMap;
import java.util.concurrent.ThreadLocalRandom;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    }

    @Test
    void testDefaultConstructor() {
        new StatusListProtocolMapper();
    }

    @Test
    void testGetMetadataAttributePath() {
        assertEquals(Constants.STATUS_CLAIM_KEY, mapper.getMetadataAttributePath().get(0));
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
        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor = ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
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
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString(String.format(
                "Running status list has reached max entries (%d), generating new list ID",
                StatusListConfig.DEFAULT_MAX_ENTRIES))));
    }

    @Test
    void shouldNotMap_IfFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn("false");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString("Status list is disabled")));
    }

    @Test
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("invalid-url");

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
    }

    @Test
    void shouldNotMap_IfDbPersistenceFails() {
        mockGetNextIndex();
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaim(claims, userSession);

        assertThat(
                "Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to initiate index mapping")));
    }

    @Test
    void shouldStillMap_IfDbPersistenceFailsAfterPublishingStatus() {
        mockGetNextIndex();
        doThrow(new PersistenceException("DB Error")).when(entityManager).merge(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should be mapped regardless", claims.keySet(),
                hasItem(Constants.STATUS_CLAIM_KEY));
        assertThat(logCaptor.getErrorLogs(),
                hasItem(containsString("Failed to persist completion mapping status")));
    }

    @Test
    void shouldNotMap_WhenSendingStatusFails() throws Exception {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService).publishOrUpdate(any(StatusListService.StatusListPayload.class));

        // Act
        mapper.setClaim(claims, userSession);

        // Assert
        assertThat("Claims should remain unmapped", claims.keySet(),
                not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(),
                hasItems(containsString("Failed to send token status")));
        assertThat(logCaptor.getDebugLogs(),
                hasItems(containsString("Persisting completion mapping status: FAILURE")));
        assertThat(logCaptor.getWarnLogs(),
                hasItem(containsString("Status list publication failed; proceeding without status claim")));
    }

    @Test
    void shouldContinueIssuance_WhenOptionalAndDbPersistenceFails() {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaim(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getWarnLogs(), hasItem(containsString("Status list publication failed; proceeding without status claim")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndDbPersistenceFails() {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndSendingStatusFails() throws Exception {
        mockGetNextIndex();
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService).publishOrUpdate(any(StatusListService.StatusListPayload.class));

        assertThrows(RuntimeException.class, () -> mapper.setClaim(claims, userSession));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    private void mockDefaultRealmConfig() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_ENABLED));
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn(TEST_SERVER_URL);
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MANDATORY));
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_MAX_ENTRIES))
                .thenReturn(String.valueOf(StatusListConfig.DEFAULT_MAX_ENTRIES));
    }

    private void mockStatusListRepository(long maxIdx) {
        statusListRepository = spy(new StatusListRepository(session));
        setPrivateField(statusListRepository, "session", session);
        setPrivateField(mapper, "statusListRepository", statusListRepository);

        var mapping = new StatusListMappingEntity();
        mapping.setStatusListId(TEST_LIST_ID);
        mapping.setIdx(maxIdx);

        lenient().doReturn(mapping)
                .when(statusListRepository)
                .getLatestMapping(anyString());
    }

    private long mockGetNextIndex() {
        long nextIndex = ThreadLocalRandom.current()
                .nextLong(StatusListConfig.DEFAULT_MAX_ENTRIES - 1);

        lenient().doReturn(nextIndex)
                .when(statusListRepository)
                .getNextIndex(any(), anyString());

        return nextIndex;
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        return UriBuilder.fromUri(TEST_SERVER_URL)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
    }
}
