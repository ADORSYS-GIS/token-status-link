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

import org.keycloak.jose.jws.JWSHeader; // Correct import for Keycloak's JWSHeader
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
    private NonceService nonceService; // Add mock for NonceService
    
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
        service = new SdJwtVPValidationService(session, nonceService); // Pass nonceService to constructor
        
        try {
            // Inject mocked JwksService
            java.lang.reflect.Field jwksField = SdJwtVPValidationService.class.getDeclaredField("jwksService");
            jwksField.setAccessible(true);
            jwksField.set(service, jwksService);
            
            // Inject mocked session
            java.lang.reflect.Field sessionField = SdJwtVPValidationService.class.getDeclaredField("session");
            sessionField.setAccessible(true);
            sessionField.set(service, session);

            // Inject mocked NonceService
            java.lang.reflect.Field nonceServiceField = SdJwtVPValidationService.class.getDeclaredField("nonceService");
            nonceServiceField.setAccessible(true);
            nonceServiceField.set(service, nonceService);

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
        String revocationEndpoint = "http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/revoke";

        IssuerSignedJWT issuerSignedJwtMock = mock(IssuerSignedJWT.class);
        JsonNode issuerSignedPayloadMock = mock(JsonNode.class);
        JWSHeader issuerSignedHeaderMock = mock(JWSHeader.class);
        JsonNode issNodeMock = mock(JsonNode.class);

        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJwtMock);
        when(issuerSignedJwtMock.getPayload()).thenReturn(issuerSignedPayloadMock);
        when(issuerSignedJwtMock.getHeader()).thenReturn(issuerSignedHeaderMock);
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
        when(audNodeMock.asText()).thenReturn(revocationEndpoint);

        // Mock nonceService.validateNonce to return false
        when(nonceService.validateNonce(eq(requestId), eq("some-nonce"), eq(revocationEndpoint))).thenReturn(false);

        // Mock KeycloakUriInfo and RealmModel for getRevocationEndpointUrl
        org.keycloak.models.KeycloakUriInfo uriInfoMock = mock(org.keycloak.models.KeycloakUriInfo.class);
        when(session.getContext().getUri()).thenReturn(uriInfoMock);
        when(uriInfoMock.getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        when(session.getContext().getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
        when(session.getContext().getRealm().getName()).thenReturn("test-realm");


        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.verifySdJwtVPSignature(sdJwtVP, requestId);
        });

        assertTrue(exception.getMessage().contains("SD-JWT VP issuer verification failed: Malformed VP: Invalid or replayed nonce, or audience mismatch"));
        assertEquals(401, exception.getHttpStatus());
    }

    @Test
    void testVerifyHolderSignatureAndKeyBinding_NonceValidationFailure() throws StatusListException {
        // Arrange
        String requestId = "test-request-id";
        String issuer = "test-issuer";
        String revocationEndpoint = "http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/revoke";

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
        when(audNodeMock.asText()).thenReturn(revocationEndpoint);

        // Mock nonceService.validateNonce to return false
        when(nonceService.validateNonce(eq(requestId), eq("some-nonce"), eq(revocationEndpoint))).thenReturn(false);

        // Mock KeycloakUriInfo and RealmModel for getRevocationEndpointUrl
        org.keycloak.models.KeycloakUriInfo uriInfoMock = mock(org.keycloak.models.KeycloakUriInfo.class);
        when(session.getContext().getUri()).thenReturn(uriInfoMock);
        when(uriInfoMock.getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        when(session.getContext().getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
        when(session.getContext().getRealm().getName()).thenReturn("test-realm");

        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.verifyHolderSignatureAndKeyBinding(sdJwtVP, requestId);
        });

        assertTrue(exception.getMessage().contains("Invalid holder proof: Holder signature verification failed: Malformed VP: Invalid or replayed nonce, or audience mismatch"));
        assertEquals(401, exception.getHttpStatus());
    }
}
