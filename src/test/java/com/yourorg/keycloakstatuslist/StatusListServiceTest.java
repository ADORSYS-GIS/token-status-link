//package com.yourorg.keycloakstatuslist;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//
//import java.time.Instant;
//
//import com.adorsys.keycloakstatuslist.service.StatusListService;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import com.adorsys.keycloakstatuslist.config.StatusListConfig;
//import com.adorsys.keycloakstatuslist.model.TokenStatus;
//
//public class StatusListServiceTest {
//
//    private StatusListConfig mockConfig;
//    private StatusListService statusListService;
//
//    @BeforeEach
//    public void setup() {
//        // Create mock config
//        mockConfig = mock(StatusListConfig.class);
//
//        // Configure default behavior
//        when(mockConfig.isEnabled()).thenReturn(true);
//        when(mockConfig.getServerUrl()).thenReturn("http://localhost:8090/api/v1/token-status");
//        when(mockConfig.getAuthToken()).thenReturn("test-token");
//        when(mockConfig.getConnectTimeout()).thenReturn(5000);
//        when(mockConfig.getReadTimeout()).thenReturn(5000);
//        when(mockConfig.getRetryCount()).thenReturn(3);
//
//        // Create service
//        statusListService = new StatusListService(mockConfig);
//    }
//
//    @Test
//    public void testDisabledService() {
//        // Configure config to be disabled
//        when(mockConfig.isEnabled()).thenReturn(false);
//
//        // Create token status
//        TokenStatus tokenStatus = createTokenStatus();
//
//        // Publish token status (should return false immediately)
//        boolean result = statusListService.publishTokenStatus(tokenStatus);
//
//        // Verify result
//        assertFalse(result);
//    }
//
//    // Ideally, we would add more tests that use a mock HTTP server to test the actual HTTP calls
//    // However, that would require additional dependencies and setup
//    // For a real project, consider using WireMock or a similar library for this
//
//    private TokenStatus createTokenStatus() {
//        TokenStatus tokenStatus = new TokenStatus();
//        tokenStatus.setTokenId("test-token-id");
//        tokenStatus.setUserId("test-user-id");
//        tokenStatus.setStatus("ACTIVE");
//        tokenStatus.setIssuer("test-realm");
//        tokenStatus.setClientId("test-client");
//        tokenStatus.setIssuedAt(Instant.now());
//        tokenStatus.setExpiresAt(Instant.now().plusSeconds(3600));
//        return tokenStatus;
//    }
//}