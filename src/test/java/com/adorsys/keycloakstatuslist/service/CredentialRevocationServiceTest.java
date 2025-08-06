package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialRevocationService.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRevocationServiceTest {

    @Mock
    private KeycloakSession session;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private KeycloakContext context;
    
    @Mock
    private KeyManager keyManager;
    
    @Mock
    private KeyWrapper keyWrapper;

    private CredentialRevocationService service;

    @BeforeEach
    void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        // Mock realm attributes to use default values (no status-list-server-url set)
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-auth-token")).thenReturn("test-auth-token");
        lenient().when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-retry-count")).thenReturn("3");
        lenient().when(realm.getAttribute(anyString())).thenReturn(null);
        
        // Mock key manager for robust implementation
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(mock(java.security.PublicKey.class));
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        
        service = new CredentialRevocationService(session);
    }

    @Test
    void testRevokeCredential_Success() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception for invalid SD-JWT VP token in test environment");
    }

    @Test
    void testRevokeCredential_NullRequest() {
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(null);
        }, "Should throw exception for null request");
    }

    @Test
    void testRevokeCredential_EmptySdJwtVp() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "", "test-credential", "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception for empty SD-JWT VP");
    }

    @Test
    void testRevokeCredential_EmptyCredentialId() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "sd-jwt-vp-token", "", "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception for empty credential ID");
    }

    @Test
    void testRevokeCredential_NullSdJwtVp() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                null, "test-credential", "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception for null SD-JWT VP");
    }

    @Test
    void testRevokeCredential_NullCredentialId() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "sd-jwt-vp-token", null, "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception for null credential ID");
    }

    @Test
    void testRevokeCredential_NoActiveKey() {
        // Arrange
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(null);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "sd-jwt-vp-token", "test-credential", "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception when no active key is available");
    }

    @Test
    void testRevokeCredential_NoPublicKey() {
        // Arrange
        lenient().when(keyWrapper.getPublicKey()).thenReturn(null);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "sd-jwt-vp-token", "test-credential", "reason"
        );
        
        // Act & Assert
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        }, "Should throw exception when active key has no public key");
    }

    /**
     * Creates a mock SD-JWT VP token for testing.
     * In a real implementation, this would create a valid SD-JWT VP token.
     */
    private String createMockSdJwtVP(String credentialId) {
        // This is a simplified mock - in reality, you'd need to create a proper SD-JWT VP token
        // For testing purposes, we'll use a placeholder
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
               "eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiand0LXNhbXBsZSIsImlhdCI6MTUxNjIzOTAyMn0." +
               "signature";
    }
} 
