package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Collections;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for DefaultSdJwtVPValidationService. Tests core: parse validation (null/empty/format),
 * verify when no verifiers (401), extractNonce (absent vs present), extractIssuer (payload).
 * Mocking: only session context and JwksService (boundaries). SdJwtVP/KeyBindingJWT mocked only
 * where real instances cannot be built without a full token.
 */
@ExtendWith(MockitoExtension.class)
class SdJwtVPValidationServiceTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private JwksService jwksService;

    @Mock
    private SignatureVerifierContext verifierContext;

    @Mock
    private SdJwtVP sdJwtVP;

    @Mock
    private KeycloakUriInfo uriInfo;

    @Mock
    private RealmModel realm;

    private DefaultSdJwtVPValidationService service;

    @BeforeEach
    void setUp() {
        service = new DefaultSdJwtVPValidationService(session, jwksService);
        lenient().when(session.getContext()).thenReturn(context);
    }

    @Test
    void parseAndValidateSdJwtVP_nullToken_throws() {
        StatusListException ex =
                assertThrows(StatusListException.class, () -> service.parseAndValidateSdJwtVP(null, "req"));
        assertTrue(ex.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void parseAndValidateSdJwtVP_emptyToken_throws() {
        StatusListException ex =
                assertThrows(StatusListException.class, () -> service.parseAndValidateSdJwtVP("", "req"));
        assertTrue(ex.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void parseAndValidateSdJwtVP_whitespaceToken_throws() {
        StatusListException ex =
                assertThrows(StatusListException.class, () -> service.parseAndValidateSdJwtVP("   ", "req"));
        assertTrue(ex.getMessage().contains("SD-JWT VP token is empty or null"));
    }

    @Test
    void parseAndValidateSdJwtVP_invalidFormat_throws() {
        StatusListException ex = assertThrows(
                StatusListException.class, () -> service.parseAndValidateSdJwtVP("invalid.token.format", "req"));
        assertTrue(ex.getMessage().contains("Invalid SD-JWT VP token format"));
    }

    @Test
    void verifySdJwtVP_noVerifierContexts_throws401() throws Exception {
        String requestId = "req";
        lenient().when(context.getUri()).thenReturn(uriInfo);
        lenient().when(uriInfo.getBaseUri()).thenReturn(java.net.URI.create("http://localhost:8080/auth/"));
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getName()).thenReturn("test-realm");
        when(jwksService.getSignatureVerifierContexts(any(SdJwtVP.class), eq(requestId)))
                .thenReturn(Collections.emptyList());

        ObjectNode payload = mock(ObjectNode.class);
        IssuerSignedJWT issuerSignedJWT = mock(IssuerSignedJWT.class);
        JsonNode issNode = mock(JsonNode.class);
        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJWT);
        when(issuerSignedJWT.getPayload()).thenReturn(payload);
        when(payload.get("iss")).thenReturn(issNode);
        when(issNode.asText()).thenReturn("test-issuer");

        StatusListException ex = assertThrows(
                StatusListException.class, () -> service.verifySdJwtVP(sdJwtVP, requestId, "expected-nonce"));

        assertTrue(ex.getMessage().contains("No public keys available")
                || ex.getMessage().contains("SD-JWT VP verification failed"));
        assertEquals(401, ex.getHttpStatus());
    }

    @Test
    void extractNonceFromKeyBindingJWT_returnsNullWhenNoKeyBindingJwt() {
        when(sdJwtVP.getKeyBindingJWT()).thenReturn(Optional.empty());
        assertNull(service.extractNonceFromKeyBindingJWT(sdJwtVP));
    }

    @Test
    void extractNonceFromKeyBindingJWT_returnsNonceWhenPresent() {
        KeyBindingJWT kbJwt = mock(KeyBindingJWT.class);
        ObjectNode payload = mock(ObjectNode.class);
        JsonNode nonceNode = mock(JsonNode.class);
        when(sdJwtVP.getKeyBindingJWT()).thenReturn(Optional.of(kbJwt));
        when(kbJwt.getPayload()).thenReturn(payload);
        when(payload.get("nonce")).thenReturn(nonceNode);
        when(nonceNode.isTextual()).thenReturn(true);
        when(nonceNode.asText()).thenReturn("presented-nonce");

        assertEquals("presented-nonce", service.extractNonceFromKeyBindingJWT(sdJwtVP));
    }

    @Test
    void extractIssuerFromToken_returnsIssuerFromPayload() {
        IssuerSignedJWT issuerSignedJWT = mock(IssuerSignedJWT.class);
        ObjectNode payload = mock(ObjectNode.class);
        JsonNode issNode = mock(JsonNode.class);
        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJWT);
        when(issuerSignedJWT.getPayload()).thenReturn(payload);
        when(payload.get("iss")).thenReturn(issNode);
        when(issNode.asText()).thenReturn("https://issuer.example.com");

        String issuer = service.extractIssuerFromToken(sdJwtVP);
        assertEquals("https://issuer.example.com", issuer);
    }

    @Test
    void extractIssuerFromToken_returnsNullWhenPayloadNull() {
        IssuerSignedJWT issuerSignedJWT = mock(IssuerSignedJWT.class);
        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJWT);
        when(issuerSignedJWT.getPayload()).thenReturn(null);

        assertNull(service.extractIssuerFromToken(sdJwtVP));
    }
}
