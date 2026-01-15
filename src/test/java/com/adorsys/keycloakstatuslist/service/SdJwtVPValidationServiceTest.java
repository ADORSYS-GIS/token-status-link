package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.*;

import com.adorsys.keycloakstatuslist.exception.StatusListException;

import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
    private PublicKey publicKey;

    private DefaultSdJwtVPValidationService service;

    @BeforeEach
    void setUp() {
        service = new DefaultSdJwtVPValidationService(session, jwksService);
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

        assertTrue(exception.getMessage().contains("Invalid SD-JWT VP token format"));
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_Success() throws Exception {
        // Test successful creation of SignatureVerifierContext
        SignatureVerifierContext result = service.createSignatureVerifierContextFromPublicKey(publicKey, "RS256");

        assertNotNull(result);
        // Verify it's the correct type
        assertInstanceOf(AsymmetricSignatureVerifierContext.class, result);
    }

    @Test
    void testCreateSignatureVerifierContextFromPublicKey_WithECAlgorithm() throws Exception {
        // Test with EC algorithm
        SignatureVerifierContext result = service.createSignatureVerifierContextFromPublicKey(publicKey, "ES256");

        assertNotNull(result);
        assertInstanceOf(AsymmetricSignatureVerifierContext.class, result);
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
