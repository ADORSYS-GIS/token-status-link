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
        
        // Mock the service to return a Status with the expected URI
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        Status expectedStatus = new Status(new StatusListClaim(idx, expectedUri));
        when(statusListService.registerAndPublishStatus(TEST_REALM_ID, idx))
                .thenReturn(expectedStatus);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assertions
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));

        // Verify service was called with correct parameters
        verify(statusListService).registerAndPublishStatus(TEST_REALM_ID, idx);
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
        
        // Mock HTTP failure
        doThrow(new StatusListException("Server not reachable"))
                .when(statusListService)
                .registerAndPublishStatus(anyString(), anyLong());
        
        // Mock fallback URI retrieval
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed even if HTTP fails
        // The mapper returns a Status with the stored index and URI
        assertThat(
                "Claims should be mapped even when HTTP fails", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify HTTP was attempted
        verify(statusListService).registerAndPublishStatus(TEST_REALM_ID, idx);
        // Verify fallback was used
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // Verify error was logged
        assertThat(logCaptor.getErrorLogs(), 
                hasItem(containsString("Failed to publish status to server")));
    }

    @Test
    void shouldMap_WhenCircuitBreakerIsOpen() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock circuit breaker open exception (wrapped in StatusListException)
        doThrow(new StatusListException("Circuit breaker is open: Circuit breaker 'test' is OPEN. Failing fast."))
                .when(statusListService)
                .registerAndPublishStatus(anyString(), anyLong());
        
        // Mock fallback URI retrieval
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed even when circuit breaker is open
        assertThat(
                "Claims should be mapped even when circuit breaker is open", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify HTTP was attempted (circuit breaker check happens in HTTP client)
        verify(statusListService).registerAndPublishStatus(TEST_REALM_ID, idx);
        // Verify fallback was used
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // Verify error was logged
        assertThat(logCaptor.getErrorLogs(), 
                hasItem(containsString("Failed to publish status to server")));
    }

    @Test
    void shouldMap_WhenHttpCallTimesOut() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Mock HTTP timeout (simulating slow server)
        doThrow(new StatusListException("Timeout publishing status list", 
                new java.io.InterruptedIOException("Read timed out")))
                .when(statusListService)
                .registerAndPublishStatus(anyString(), anyLong());
        
        // Mock fallback URI retrieval
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert - token issuance should proceed even when HTTP times out
        assertThat(
                "Claims should be mapped even when HTTP times out", 
                claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify HTTP was attempted
        verify(statusListService).registerAndPublishStatus(TEST_REALM_ID, idx);
        // Verify fallback was used
        verify(statusListService).getStatusListUri(TEST_REALM_ID);
        // Verify timeout error was logged
        assertThat(logCaptor.getErrorLogs(), 
                hasItem(containsString("Failed to publish status to server")));
    }

    @Test
    void shouldCompleteTransaction_BeforeHttpCall() throws Exception {
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        Status expectedStatus = new Status(new StatusListClaim(idx, expectedUri));
        
        // Use Answer to verify transaction completes before HTTP call
        when(statusListService.registerAndPublishStatus(TEST_REALM_ID, idx))
                .thenAnswer(invocation -> {
                    // Verify entity was already persisted (transaction completed)
                    verify(entityManager, atLeastOnce()).persist(any(StatusListMappingEntity.class));
                    verify(entityManager, atLeastOnce()).flush();
                    return expectedStatus;
                });

        // Act
        mapper.setClaimsForSubject(claims, userSession);

        // Assert
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, expectedUri)));
        
        // Verify order: DB operations complete before HTTP call
        // The Answer above already verified this, but we can also check the sequence
        verify(entityManager).persist(any(StatusListMappingEntity.class));
        verify(entityManager).flush();
        verify(statusListService).registerAndPublishStatus(TEST_REALM_ID, idx);
    }

    @Test
    void shouldNotBlockTokenIssuance_WhenHttpIsSlow() throws Exception {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_MANDATORY)).thenReturn("false");
        long idx = mockEntityPersist();
        String expectedUri = TEST_SERVER_URL + "statuslists/" + TEST_REALM_ID;
        
        // Simulate slow HTTP call (but don't actually wait - just verify fallback works)
        doThrow(new StatusListException("Server slow response"))
                .when(statusListService)
                .registerAndPublishStatus(anyString(), anyLong());
        
        when(statusListService.getStatusListUri(TEST_REALM_ID))
                .thenReturn(expectedUri);

        // Act - should return quickly even if HTTP is slow
        long startTime = System.currentTimeMillis();
        mapper.setClaimsForSubject(claims, userSession);
        long duration = System.currentTimeMillis() - startTime;

        // Assert - token issuance completed (with fallback)
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertThat("Should complete quickly (fallback used)", duration, lessThan(1000L));
        
        // Verify the returned status has the correct index
        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList().getIdx(), equalTo(idx));
        
        // Verify fallback was used
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
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Status list is mandatory and publication failed; failing issuance")));
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
