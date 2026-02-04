package com.adorsys.keycloakstatuslist;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity.MappingStatus;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.PersistenceException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

class StatusListProtocolMapperTest extends MockKeycloakTest {

    protected static final String TEST_SERVER_URL = "https://example.com";
    LogCaptor logCaptor = LogCaptor.forClass(StatusListProtocolMapper.class);

    @Mock
    ProtocolMapperModel mapperModel;

    @Mock
    StatusListService statusListService;

    StatusListProtocolMapper mapper;
    HashMap<String, Object> claims;

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
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, listUri(TEST_REALM_ID))));

        // 2. Verify service was called with correct payload
        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).publishOrUpdate(payloadCaptor.capture());
        StatusListService.StatusListPayload capturedPayload = payloadCaptor.getValue();
        assertThat(capturedPayload.listId(), equalTo(TEST_REALM_ID));
        assertThat(capturedPayload.status().size(), equalTo(1));
        assertThat(capturedPayload.status().get(0).index(), equalTo((int) idx));
        assertThat(capturedPayload.status().get(0).status(), equalTo(Constants.TOKEN_STATUS_VALID));

        // 3. Verify DB persist was called
        var entityCaptor = ArgumentCaptor.forClass(StatusListMappingEntity.class);
        verify(entityManager).persist(entityCaptor.capture());
        StatusListMappingEntity capturedEntity = entityCaptor.getValue();
        assertEquals(idx, capturedEntity.getIdx());
        assertEquals(TEST_REALM_ID, capturedEntity.getRealmId());
        assertEquals(MappingStatus.SUCCESS, capturedEntity.getStatus());
    }

    @Test
    void shouldNotMap_IfFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("false");

        mapper.setClaim(claims, userSession);

        assertThat(
                "Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString("Status list is disabled")));
    }

    @Test
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn("invalid-url");

        mapper.setClaim(claims, userSession);

        assertThat(
                "Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
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
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService)
                .publishOrUpdate(any(StatusListService.StatusListPayload.class));

        // Act
        mapper.setClaim(claims, userSession);

        // Assert
        assertThat("Claims should remain unmapped", claims.keySet(),
                not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(),
                hasItems(containsString("Failed to send token status")));
        assertThat(logCaptor.getDebugLogs(),
                hasItems(containsString("Persisting completion mapping status: FAILURE")));
    }

    private void mockDefaultRealmConfig() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn(TEST_SERVER_URL);
    }

    @SuppressWarnings("unchecked")
    private long mockGetNextIndex() {
        long nextIndex = ThreadLocalRandom.current().nextLong(Long.MAX_VALUE);
        var query = mock(TypedQuery.class);

        when(entityManager.createQuery(anyString(), eq(StatusListMappingEntity.class))).thenReturn(query);
        when(query.getResultList()).thenAnswer(invocation -> {
            var entity = new StatusListMappingEntity();
            entity.setIdx(nextIndex - 1);
            return List.of(entity);
        });

        return nextIndex;
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        return UriBuilder.fromUri(TEST_SERVER_URL)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
    }
}
