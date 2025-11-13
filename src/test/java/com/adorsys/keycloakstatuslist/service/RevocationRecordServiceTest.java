package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
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

import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RevocationRecordService.
 */
@ExtendWith(MockitoExtension.class)
class RevocationRecordServiceTest {

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
    
    @Mock
    private PublicKey publicKey;

    private RevocationRecordService service;

    @BeforeEach
    void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        service = new RevocationRecordService(session);
    }

    @Test
    void testCreateRevocationRecord_Success() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertNotNull(result);
        assertEquals(credentialId, result.getCredentialId());
        assertEquals("test-realm", result.getIssuer());
        assertEquals("test-realm", result.getIssuerId());
        assertEquals("-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString("test-public-key".getBytes()) + "\n-----END PUBLIC KEY-----", result.getPublicKey());
        assertEquals("RS256", result.getAlg());
        assertEquals(TokenStatus.REVOKED.getValue(), result.getStatus());
        assertEquals("oauth2", result.getCredentialType());
        assertNotNull(result.getRevokedAt());
        assertEquals(revocationReason, result.getStatusReason());
    }

    @Test
    void testCreateRevocationRecord_WithNullReason() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, null
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertNotNull(result);
        assertEquals("Credential revoked", result.getStatusReason());
    }

    @Test
    void testCreateRevocationRecord_WithEmptyReason() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, ""
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertNotNull(result);
        assertEquals("Credential revoked", result.getStatusReason());
    }

    @Test
    void testCreateRevocationRecord_NoActiveKey() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager to return null
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(null);
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });
        
        assertTrue(exception.getMessage().contains("No active signing key found for realm"));
    }

    @Test
    void testCreateRevocationRecord_KeyWithoutPublicKey() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager to return key without public key
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(null);
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });
        
        assertTrue(exception.getMessage().contains("Active key has no public key for realm"));
    }

    @Test
    void testCreateRevocationRecord_KeyWithNullAlgorithm() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn(null);
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert - should default to RS256
        assertNotNull(result);
        assertEquals("RS256", result.getAlg());
    }

    @Test
    void testCreateRevocationRecord_KeyWithDifferentAlgorithm() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("ES256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertNotNull(result);
        assertEquals("ES256", result.getAlg());
    }

    @Test
    void testCreateRevocationRecord_KeyManagerException() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager to throw exception
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256")))
            .thenThrow(new RuntimeException("Key manager error"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });
        
        assertTrue(exception.getMessage().contains("Failed to retrieve realm public key"));
    }

    @Test
    void testValidateRevocationReason_NullReason() {
        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            service.validateRevocationReason(null);
        });
    }

    @Test
    void testValidateRevocationReason_EmptyReason() {
        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            service.validateRevocationReason("");
        });
    }

    @Test
    void testValidateRevocationReason_ShortReason() {
        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            service.validateRevocationReason("Short reason");
        });
    }

    @Test
    void testValidateRevocationReason_ExactLengthReason() {
        // Arrange
        String reason = "a".repeat(255);
        
        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            service.validateRevocationReason(reason);
        });
    }

    @Test
    void testValidateRevocationReason_TooLongReason() {
        // Arrange
        String reason = "a".repeat(256);
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationReason(reason);
        });
        
        assertTrue(exception.getMessage().contains("Revocation reason exceeds maximum length of 255 characters"));
    }

    @Test
    void testCreateRevocationRecord_VerifyRevokedAtTimestamp() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertNotNull(result.getRevokedAt());
        // Just verify that the timestamp is not null and is a reasonable value
        // The exact timing is not critical for the functionality
        assertTrue(result.getRevokedAt().isAfter(Instant.now().minusSeconds(10))); // Should be within last 10 seconds
    }

    @Test
    void testCreateRevocationRecord_VerifyRealmName() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        String realmName = "custom-realm-name";
        
        when(realm.getName()).thenReturn(realmName);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertEquals(realmName, result.getIssuer());
        assertEquals(realmName, result.getIssuerId());
    }

    @Test
    void testCreateRevocationRecord_VerifyCredentialType() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertEquals("oauth2", result.getCredentialType());
    }

    @Test
    void testCreateRevocationRecord_VerifyTokenStatus() throws Exception {
        // Arrange
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );
        
        // Mock key manager
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        when(publicKey.getEncoded()).thenReturn("test-public-key".getBytes());
        
        // Act
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        
        // Assert
        assertEquals(TokenStatus.REVOKED.getValue(), result.getStatus());
    }

    // The toPem method in the service now returns the full PEM format, so the test should expect that.
    // This helper method is no longer needed as the service itself formats the key.
    // private String toPem(String base64Key) {
    //     return "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(base64Key.getBytes()) + "\n-----END PUBLIC KEY-----";
    // }
}
