package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SdJwtVPValidationService.
 */
@ExtendWith(MockitoExtension.class)
class SdJwtVPValidationServiceTest {

    @Mock
    private KeycloakSession session;
    
    @Mock
    private JwksService jwksService;
    
    @Mock
    private org.keycloak.models.KeycloakContext context;
    
    @Mock
    private SdJwtVP sdJwtVP;
    
    @Mock
    private PublicKey publicKey;
    
    @Mock
    private SignatureVerifierContext verifierContext;

    private SdJwtVPValidationService service;

    @BeforeEach
    void setUp() {
        service = new SdJwtVPValidationService(session);
        
        try {
            // Inject mocked JwksService
            java.lang.reflect.Field jwksField = SdJwtVPValidationService.class.getDeclaredField("jwksService");
            jwksField.setAccessible(true);
            jwksField.set(service, jwksService);
            
            // Inject mocked session
            java.lang.reflect.Field sessionField = SdJwtVPValidationService.class.getDeclaredField("session");
            sessionField.setAccessible(true);
            sessionField.set(service, session);
        } catch (Exception e) {
            fail("Failed to inject mocked dependencies: " + e.getMessage());
        }
    }
    @Test
    void testParseAndValidateSdJwtVP_NullToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseAndValidateSdJwtVP(null, "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseAndValidateSdJwtVP_EmptyToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseAndValidateSdJwtVP("", "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseAndValidateSdJwtVP_WhitespaceToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseAndValidateSdJwtVP("   ", "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseAndValidateSdJwtVP_InvalidFormat() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseAndValidateSdJwtVP("invalid.token.format", "test-request-id");
        });
        
        // The underlying library may throw different exceptions, so we just check that *some* exception is thrown.
        assertNotNull(exception);
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_Success() throws Exception {
        // Test successful creation of SignatureVerifierContext
        SignatureVerifierContext result = service.createSignatureVerifierContextFromPublicKey(publicKey, "RS256");
        
        assertNotNull(result);
        // Verify it's the correct type
        assertTrue(result instanceof org.keycloak.crypto.AsymmetricSignatureVerifierContext);
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_WithECAlgorithm() throws Exception {
        // Test with EC algorithm
        SignatureVerifierContext result = service.createSignatureVerifierContextFromPublicKey(publicKey, "ES256");
        
        assertNotNull(result);
        assertTrue(result instanceof org.keycloak.crypto.AsymmetricSignatureVerifierContext);
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_NullPublicKey() {
        // Test with null public key
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createSignatureVerifierContextFromPublicKey(null, "RS256");
        });
        
        assertTrue(exception.getMessage().contains("Failed to create signature verifier context from public key"));
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_NullAlgorithm() {
        // Test with null algorithm
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createSignatureVerifierContextFromPublicKey(publicKey, null);
        });
        
        assertTrue(exception.getMessage().contains("Failed to create signature verifier context from public key"));
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_EmptyAlgorithm() {
        // Test with empty algorithm
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createSignatureVerifierContextFromPublicKey(publicKey, "");
        });
        
        assertTrue(exception.getMessage().contains("Failed to create signature verifier context from public key"));
    }
} 
