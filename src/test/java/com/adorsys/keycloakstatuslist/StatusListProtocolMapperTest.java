package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
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
import java.util.Random;
import java.util.UUID;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class StatusListProtocolMapperTest extends MockKeycloakTest {

    LogCaptor logCaptor = LogCaptor.forClass(StatusListProtocolMapper.class);

    protected static final String TEST_SERVER_URL = "https://example.com";

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
    void shouldMapSuccessfully_WhenStatusIsSent() throws Exception {
        long idx = mockEntityPersist();

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assertions
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, listUri(TEST_REALM_ID))));

        // 2. Verify service was called with correct payload
        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor = ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).publishOrUpdate(payloadCaptor.capture());
        StatusListService.StatusListPayload capturedPayload = payloadCaptor.getValue();
        assertThat(capturedPayload.listId(), equalTo(TEST_REALM_ID));
        assertThat(capturedPayload.status().size(), equalTo(1));
        assertThat(capturedPayload.status().get(0).index(), equalTo((int) idx));
        assertThat(capturedPayload.status().get(0).status(), equalTo(Constants.TOKEN_STATUS_VALID));
    }

    @Test
    void shouldNotMap_IfFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn("false");

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString("Status list is disabled")));
    }

    @Test
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("invalid-url");

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
    }

    @Test
    void shouldNotMap_IfDbPersistenceFails() {
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to store index mapping")));
    }

    @Test
    void shouldNotMap_WhenSendingStatusFails() throws Exception {
        mockEntityPersist();
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService).publishOrUpdate(any(StatusListService.StatusListPayload.class));

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert
        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItems(
                containsString("Failed to store index mapping")
        ));
    }

    private void mockDefaultRealmConfig() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(TEST_SERVER_URL);
    }

    /**
     * Mocks the EntityManager.persist() method.
     * Generates a random index and UUID to simulate database behavior.
     *
     * @return the simulated index that will be assigned to the entity
     */
    private long mockEntityPersist() {
        long simulatedIndex = new Random().nextInt(100000);

        doAnswer(invocation -> {
            StatusListMappingEntity entity = invocation.getArgument(0);
            entity.setIdx(simulatedIndex); // Simulate sequence generation
            entity.setId(UUID.randomUUID().toString()); // Simulate UUID generation
            return null;
        }).when(entityManager).persist(any(StatusListMappingEntity.class));

        return simulatedIndex;
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        return UriBuilder.fromUri(TEST_SERVER_URL)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
    }
}
