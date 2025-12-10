package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.KeyBindingJWT;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;


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

            // Mock KeycloakContext and its dependencies
            lenient().when(session.getContext()).thenReturn(context);
            lenient().when(context.getUri()).thenReturn(mock(org.keycloak.models.KeycloakUriInfo.class));
            lenient().when(context.getUri().getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
            lenient().when(context.getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
            lenient().when(context.getRealm().getName()).thenReturn("test-realm");

        } catch (Exception e) {
            fail("Failed to inject mocked dependencies: " + e.getMessage());
        }
    }
    @Test
    void testParseSdJwtVP_NullToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseSdJwtVP(null, "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseSdJwtVP_EmptyToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseSdJwtVP("", "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseSdJwtVP_WhitespaceToken() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseSdJwtVP("   ", "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void testParseSdJwtVP_InvalidFormat() {
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.parseSdJwtVP("invalid.token.format", "test-request-id");
        });
        
        assertTrue(exception.getMessage().contains("Invalid SD-JWT VP token format"));
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

    @Test
    void testVerifySdJwtVPSignature_NonceValidationFailure() throws StatusListException {
        // Arrange
        String requestId = "test-request-id";
        String issuer = "test-issuer";

        IssuerSignedJWT issuerSignedJwtMock = mock(IssuerSignedJWT.class);
        JsonNode issuerSignedPayloadMock = mock(JsonNode.class);
        JsonNode issNodeMock = mock(JsonNode.class);

        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJwtMock);
        when(issuerSignedJwtMock.getPayload()).thenReturn(issuerSignedPayloadMock);
        when(issuerSignedPayloadMock.get("iss")).thenReturn(issNodeMock);
        when(issNodeMock.asText()).thenReturn(issuer);
        when(jwksService.getSignatureVerifierContexts(any(SdJwtVP.class), eq(issuer), eq(requestId))).thenReturn(Collections.singletonList(verifierContext));

        // Mock KeyBindingJwtVerificationOpts to return a present optional with a mocked JWT
        KeyBindingJWT kbJwtMock = mock(KeyBindingJWT.class);
        JsonNode kbPayloadMock = mock(JsonNode.class);
        JsonNode nonceNodeMock = mock(JsonNode.class);
        JsonNode audNodeMock = mock(JsonNode.class);

        when(sdJwtVP.getKeyBindingJWT()).thenReturn(Optional.of(kbJwtMock));
        when(kbJwtMock.getPayload()).thenReturn(kbPayloadMock);
        when(kbPayloadMock.get("nonce")).thenReturn(nonceNodeMock);
        when(nonceNodeMock.isTextual()).thenReturn(true);
        when(nonceNodeMock.asText()).thenReturn("some-nonce");
        when(kbPayloadMock.get("aud")).thenReturn(audNodeMock);
        when(audNodeMock.isTextual()).thenReturn(true);
        // Test audience mismatch - set aud to different endpoint (this will cause validation to fail)
        lenient().when(audNodeMock.asText()).thenReturn("http://different-endpoint.com/revoke");

        // Mock credential ID extraction - mock the payload to return a credential ID
        // Note: This may not be called if validation fails early, so use lenient()
        JsonNode subNodeMock = mock(JsonNode.class);
        lenient().when(issuerSignedPayloadMock.get("sub")).thenReturn(subNodeMock);
        lenient().when(subNodeMock.asText()).thenReturn("test-credential-id");

        // Mock KeycloakUriInfo and RealmModel for getRevocationEndpointUrl
        org.keycloak.models.KeycloakUriInfo uriInfoMock = mock(org.keycloak.models.KeycloakUriInfo.class);
        when(session.getContext().getUri()).thenReturn(uriInfoMock);
        when(uriInfoMock.getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        when(session.getContext().getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
        when(session.getContext().getRealm().getName()).thenReturn("test-realm");


        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.verifySdJwtVPSignature(sdJwtVP, requestId, "test-credential-id", "expected-nonce");
        });

        assertTrue(exception.getMessage().contains("SD-JWT VP verification failed") || 
                   exception.getMessage().contains("Key Binding JWT audience does not match"));
        assertEquals(401, exception.getHttpStatus());
    }

    @Test
    void testVerifySdJwtVPSignature_MissingNonce() throws StatusListException {
        // Arrange
        String requestId = "test-request-id";
        String issuer = "test-issuer";

        IssuerSignedJWT issuerSignedJwtMock = mock(IssuerSignedJWT.class);
        JsonNode issuerSignedPayloadMock = mock(JsonNode.class);
        JsonNode issNodeMock = mock(JsonNode.class);

        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJwtMock);
        when(issuerSignedJwtMock.getPayload()).thenReturn(issuerSignedPayloadMock);
        when(issuerSignedPayloadMock.get("iss")).thenReturn(issNodeMock);
        when(issNodeMock.asText()).thenReturn(issuer);
        when(jwksService.getSignatureVerifierContexts(any(SdJwtVP.class), eq(issuer), eq(requestId))).thenReturn(Collections.singletonList(verifierContext));

        // Mock KeyBinding JWT with valid aud but test with null expectedNonce
        KeyBindingJWT kbJwtMock = mock(KeyBindingJWT.class);
        JsonNode kbPayloadMock = mock(JsonNode.class);
        JsonNode audNodeMock = mock(JsonNode.class);

        when(sdJwtVP.getKeyBindingJWT()).thenReturn(Optional.of(kbJwtMock));
        when(kbJwtMock.getPayload()).thenReturn(kbPayloadMock);
        when(kbPayloadMock.get("aud")).thenReturn(audNodeMock);
        when(audNodeMock.isTextual()).thenReturn(true);
        when(audNodeMock.asText()).thenReturn("http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/revoke");

        // Mock KeycloakUriInfo and RealmModel for getRevocationEndpointUrl
        org.keycloak.models.KeycloakUriInfo uriInfoMock = mock(org.keycloak.models.KeycloakUriInfo.class);
        when(session.getContext().getUri()).thenReturn(uriInfoMock);
        when(uriInfoMock.getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        when(session.getContext().getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
        when(session.getContext().getRealm().getName()).thenReturn("test-realm");

        // Act & Assert - Test with null expectedNonce
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.verifySdJwtVPSignature(sdJwtVP, requestId, "test-credential-id", null);
        });

        assertTrue(exception.getMessage().contains("Server-generated nonce not provided") ||
                   exception.getMessage().contains("Malformed VP") ||
                   exception.getMessage().contains("SD-JWT VP verification failed"));
        // Note: Returns 401 because the exception is caught and wrapped as authentication failure
        assertEquals(401, exception.getHttpStatus());
    }
}
