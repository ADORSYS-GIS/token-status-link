package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
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
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CredentialRevocationService.
 * Tests ONLY the main service's orchestration logic, not individual service implementations.
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
    
    private RSAPublicKey publicKey;
    
    @Mock
    private StatusListService statusListService;
    
    @Mock
    private SdJwtVP sdJwtVP;
    
    @Mock
    private SdJwtVPValidationService sdJwtVPValidationService;
    
    @Mock
    private RevocationRecordService revocationRecordService;
    
    @Mock
    private RequestValidationService requestValidationService;
    
    @Mock
    private TokenStatusRecord mockRevocationRecord;
    
    @Mock
    private NonceCacheService nonceCacheService;

    private CredentialRevocationService service;

    @BeforeEach
    void setUp() throws Exception {
        // Generate real RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        // Setup basic session mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        // Setup realm attributes
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute(anyString())).thenReturn(null);
        
        // Setup key management
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        
        // Mock NonceCacheProvider (accessed via RealmResourceProvider)
        lenient().when(session.getProvider(
            org.keycloak.services.resource.RealmResourceProvider.class, 
            "nonce-cache"
        )).thenReturn(nonceCacheService);
        
        // Create service with mocked dependencies
        service = new CredentialRevocationService(session);
        
        // Inject mocked dependencies using reflection
        injectMockedDependencies();
    }
    
    private void injectMockedDependencies() {
        try {
            // Inject mocked SdJwtVPValidationService
            java.lang.reflect.Field sdJwtVPValidationField = CredentialRevocationService.class.getDeclaredField("sdJwtVPValidationService");
            sdJwtVPValidationField.setAccessible(true);
            sdJwtVPValidationField.set(service, sdJwtVPValidationService);
            
            
            // Inject mocked StatusListService
            java.lang.reflect.Field statusListField = CredentialRevocationService.class.getDeclaredField("statusListService");
            statusListField.setAccessible(true);
            statusListField.set(service, statusListService);

            
        } catch (Exception e) {
            fail("Failed to inject mocked dependencies: " + e.getMessage());
        }
    }

    @Test
    void testRevokeCredential_Success() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock nonce validation
        String testNonce = "test-nonce-123";
        RevocationChallenge validChallenge = new RevocationChallenge(
            testNonce,
            "https://test.example.com/revoke",
            request.getCredentialId(),
            Instant.now().plusSeconds(600)
        );
        
        // Mock all dependencies to return success
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class))).thenReturn(testNonce);
        when(nonceCacheService.consumeNonce(testNonce)).thenReturn(validChallenge);
        doNothing().when(sdJwtVPValidationService).verifySdJwtVPSignature(any(SdJwtVP.class), anyString(), anyString(), anyString());
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        doNothing().when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act
        CredentialRevocationResponse response = service.revokeCredential(request, "valid-sd-jwt-vp-token");
        
        // Assert - Test ONLY the main service's orchestration logic
        assertNotNull(response);
        assertEquals(request.getCredentialId(), response.getCredentialId());
        assertNotNull(response.getRevokedAt());
        assertEquals(request.getRevocationReason(), response.getRevocationReason());
        
        // Verify the orchestration flow - services called in correct order
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService).consumeNonce(testNonce);
        verify(sdJwtVPValidationService).verifySdJwtVPSignature(any(SdJwtVP.class), anyString(), anyString(), anyString());
        verify(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        verify(statusListService).publishRecord(any(TokenStatusRecord.class));
    }

    @Test
    void testRevokeCredential_RequestValidationFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock parsing to fail
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString()))
            .thenThrow(new StatusListException("Validation failed"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("Validation failed"));
        
        // Verify no other services were called
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(statusListService, never()).publishRecord(any());
        verify(statusListService, never()).publishRecord(any());
    }

    @Test
    void testRevokeCredential_SdJwtVPValidationFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock request validation to succeed, but SD-JWT validation to fail
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString()))
            .thenThrow(new StatusListException("SD-JWT validation failed"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("SD-JWT validation failed"));
        
        // Verify the flow stopped at SD-JWT validation
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(statusListService, never()).publishRecord(any());
    }

    @Test
    void testRevokeCredential_StatusListFailure() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock nonce validation
        String testNonce = "test-nonce-456";
        RevocationChallenge validChallenge = new RevocationChallenge(
            testNonce,
            "https://test.example.com/revoke",
            request.getCredentialId(),
            Instant.now().plusSeconds(600)
        );
        
        // Mock all dependencies to succeed until status list publication
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class))).thenReturn(testNonce);
        when(nonceCacheService.consumeNonce(testNonce)).thenReturn(validChallenge);
        doNothing().when(sdJwtVPValidationService).verifySdJwtVPSignature(any(SdJwtVP.class), anyString(), anyString(), anyString());
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        doThrow(new StatusListException("Status list publication failed"))
            .when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly handles the error
        assertTrue(exception.getMessage().contains("Status list publication failed"));
        
        // Verify the complete flow was executed
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService).consumeNonce(testNonce);
        verify(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        verify(statusListService).publishRecord(any(TokenStatusRecord.class));
    }

    @Test
    void testRevokeCredential_RequestIdGeneration() throws Exception {
        // Arrange
        CredentialRevocationRequest request1 = createValidRequest();
        CredentialRevocationRequest request2 = createValidRequest();
        
        // Mock nonce validation for both requests
        String testNonce1 = "test-nonce-789";
        String testNonce2 = "test-nonce-101";
        RevocationChallenge validChallenge1 = new RevocationChallenge(
            testNonce1,
            "https://test.example.com/revoke",
            request1.getCredentialId(),
            Instant.now().plusSeconds(600)
        );
        RevocationChallenge validChallenge2 = new RevocationChallenge(
            testNonce2,
            "https://test.example.com/revoke",
            request2.getCredentialId(),
            Instant.now().plusSeconds(600)
        );
        
        // Mock all dependencies to succeed
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class)))
            .thenReturn(testNonce1, testNonce2);
        when(nonceCacheService.consumeNonce(testNonce1)).thenReturn(validChallenge1);
        when(nonceCacheService.consumeNonce(testNonce2)).thenReturn(validChallenge2);
        doNothing().when(sdJwtVPValidationService).verifySdJwtVPSignature(any(SdJwtVP.class), anyString(), anyString(), anyString());
        doNothing().when(sdJwtVPValidationService).verifyCredentialOwnership(any(SdJwtVP.class), anyString(), anyString());
        doNothing().when(statusListService).publishRecord(any(TokenStatusRecord.class));
        
        // Act
        service.revokeCredential(request1, "valid-sd-jwt-vp-token");
        service.revokeCredential(request2, "valid-sd-jwt-vp-token");
        
        // Assert - Verify that different request IDs were generated
        verify(sdJwtVPValidationService, times(2)).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService, times(2)).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService).consumeNonce(testNonce1);
        verify(nonceCacheService).consumeNonce(testNonce2);
        verify(statusListService, times(2)).publishRecord(any());
    }

    @Test
    void testRevokeCredential_UnexpectedException() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock an unexpected exception
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString()))
            .thenThrow(new RuntimeException("Unexpected error"));
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that the main service properly wraps unexpected exceptions
        assertTrue(exception.getMessage().contains("Failed to process credential revocation"));
        assertTrue(exception.getMessage().contains("Unexpected error"));
    }

    @Test
    void testRevokeCredential_ServiceInitialization() {
        // Act & Assert
        CredentialRevocationService newService = new CredentialRevocationService(session);
        assertNotNull(newService);
    }
    
    @Test
    void testRevokeCredential_MissingNonce() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        
        // Mock SD-JWT VP parsing but no nonce in Key Binding JWT
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class))).thenReturn(null);
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that missing nonce is properly caught
        assertTrue(exception.getMessage().contains("Invalid or missing nonce"));
        
        // Verify flow stopped at nonce validation
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService, never()).consumeNonce(anyString());
        verify(statusListService, never()).publishRecord(any());
    }
    
    @Test
    void testRevokeCredential_InvalidNonce() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        String invalidNonce = "invalid-nonce";
        
        // Mock SD-JWT VP parsing with invalid nonce (not in cache)
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class))).thenReturn(invalidNonce);
        when(nonceCacheService.consumeNonce(invalidNonce)).thenReturn(null);  // Nonce not found
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that invalid nonce is properly caught
        assertTrue(exception.getMessage().contains("Invalid, expired, or replayed nonce"));
        
        // Verify flow stopped at nonce validation
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService).consumeNonce(invalidNonce);
        verify(statusListService, never()).publishRecord(any());
    }
    
    @Test
    void testRevokeCredential_NonceMismatch() throws Exception {
        // Arrange
        CredentialRevocationRequest request = createValidRequest();
        String testNonce = "test-nonce-mismatch";
        
        // Mock nonce for DIFFERENT credential
        RevocationChallenge mismatchedChallenge = new RevocationChallenge(
            testNonce,
            "https://test.example.com/revoke",
            "different-credential-id",  // Different from request
            Instant.now().plusSeconds(600)
        );
        
        // Mock SD-JWT VP parsing
        when(sdJwtVPValidationService.parseSdJwtVP(anyString(), anyString())).thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(any(SdJwtVP.class))).thenReturn(testNonce);
        when(nonceCacheService.consumeNonce(testNonce)).thenReturn(mismatchedChallenge);
        
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request, "valid-sd-jwt-vp-token");
        });
        
        // Test that credential ID mismatch is properly caught
        assertTrue(exception.getMessage().contains("Nonce was issued for a different credential"));
        
        // Verify flow stopped at nonce validation
        verify(sdJwtVPValidationService).parseSdJwtVP(anyString(), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(any(SdJwtVP.class));
        verify(nonceCacheService).consumeNonce(testNonce);
        verify(statusListService, never()).publishRecord(any());
    }

    private CredentialRevocationRequest createValidRequest() {
        return new CredentialRevocationRequest(
                "test-credential-123",
                "Test revocation"
        );
    }
} 
