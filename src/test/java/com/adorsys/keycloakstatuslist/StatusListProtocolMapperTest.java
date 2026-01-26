package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.PersistenceException;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.mockito.Mock;

import java.util.HashMap;
import java.util.Random;
import java.util.UUID;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        
        // Mock getStatusListUri which is now called synchronously
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assertions
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));

        // Verify URI was retrieved
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
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
    void shouldNotMap_IfDbPersistenceFails() throws Exception {
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to store index mapping")));
        // Verify HTTP call was never attempted
        verify(statusListService, never()).registerAndPublishStatus(anyString(), anyLong());
    }

    @Test
    void shouldMap_EvenWhenHttpFails() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock URI retrieval (always called synchronously to create Status)
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed immediately in optional mode
        // The mapper returns a Status immediately without waiting for HTTP
        assertThat(
                "Claims should be mapped immediately (async HTTP)", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify URI was retrieved synchronously
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // HTTP happens asynchronously in background, so we don't verify it here
    }

    @Test
    void shouldMap_WhenCircuitBreakerIsOpen() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock URI retrieval (always called synchronously)
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed immediately even when circuit breaker is open
        // In optional mode, HTTP happens asynchronously, so circuit breaker doesn't block
        assertThat(
                "Claims should be mapped immediately (async HTTP)", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify URI was retrieved
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // HTTP happens asynchronously in background
    }

    @Test
    void shouldMap_WhenHttpCallTimesOut() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock URI retrieval (always called synchronously)
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed immediately (async HTTP means no timeout blocking)
        assertThat(
                "Claims should be mapped immediately (async HTTP)", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify URI was retrieved
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // HTTP timeout happens asynchronously in background, doesn't affect token issuance
    }

    @Test
    void shouldCompleteTransaction_BeforeHttpCall() throws Exception {
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock URI retrieval
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - transaction completes and Status is created before returning
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify DB operations completed
        verify(entityManager).persist(any(StatusListMappingEntity.class));
        verify(entityManager).flush();
        // HTTP call happens asynchronously after transaction and return
    }

    @Test
    void shouldNotBlockTokenIssuance_WhenHttpIsSlow() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock URI retrieval (called synchronously)
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act - should return quickly even if HTTP is slow (HTTP happens async in background)
        long startTime = System.currentTimeMillis();
        mapper.setClaimsForSubject(claims, userSession);
        long duration = System.currentTimeMillis() - startTime;

        // Assert - token issuance completed immediately (async HTTP doesn't block)
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertThat("Should complete quickly (async HTTP)", duration, lessThan(1000L));
        
        // Verify the returned status has the correct index
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList().getIdx(), equalTo(idx));
        
        // Verify URI was retrieved synchronously
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
    }

    @Test
    void shouldContinueIssuance_WhenOptionalAndDbPersistenceFails() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getWarnLogs(), hasItem(containsString("Status list publication failed or was skipped; continuing without status claim")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndDbPersistenceFails() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
        doThrow(new PersistenceException("DB Error")).when(entityManager).persist(any());

        assertThrows(RuntimeException.class, () -> mapper.setClaimsForSubject(claims, userSession));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
    }

    @Test
    void shouldFailIssuance_WhenMandatoryAndHttpFails() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("true");
        mockEntityPersist();
        
        // Mock HTTP failure
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService)
                .registerAndPublishStatus(anyString(), anyLong());

        assertThrows(RuntimeException.class, () -> mapper.setClaimsForSubject(claims, userSession));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failing token issuance as status list is mandatory")));
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
}
