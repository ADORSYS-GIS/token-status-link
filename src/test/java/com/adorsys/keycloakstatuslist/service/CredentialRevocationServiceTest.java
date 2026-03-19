package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheServiceProviderFactory;
import com.adorsys.keycloakstatuslist.service.validation.SdJwtVPValidationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.resource.RealmResourceProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for CredentialRevocationService. Tests core: orchestration order (parse → nonce →
 * verify → build payload → update status list), error handling at each step, and payload built from VP.
 * Mocking: only boundaries (session, StatusListService, SdJwtVPValidationService, NonceCacheProvider)
 * and Keycloak token types (SdJwtVP/IssuerSignedJWT) that cannot be constructed without a real token.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRevocationServiceTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private StatusListService statusListService;

    @Mock
    private SdJwtVPValidationService sdJwtVPValidationService;

    @Mock
    private NonceCacheService nonceCacheService;

    @Mock
    private SdJwtVP sdJwtVP;

    private CredentialRevocationService service;

    @BeforeEach
    void setUp() {
        service = new CredentialRevocationService(session, statusListService, sdJwtVPValidationService);
        lenient()
                .when(session.getProvider(
                        eq(RealmResourceProvider.class), eq(NonceCacheServiceProviderFactory.PROVIDER_ID)))
                .thenReturn((RealmResourceProvider) nonceCacheService);
    }

    @Test
    void revokeCredential_success_returnsResponse() throws Exception {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);
        request.setRevocationReason("User requested revocation");

        String token = "sd-jwt-vp-token";
        String nonce = "nonce-123";
        RevocationChallenge challenge = new RevocationChallenge(nonce, "https://example.com/revoke", 600);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode statusNode = mapper.createObjectNode();
        ObjectNode statusListNode = statusNode.putObject("status_list");
        statusListNode.put("idx", 1L).put("uri", "https://example.com/statuslists/list-1");
        ObjectNode issuerPayload = mapper.createObjectNode();
        issuerPayload.set("status", statusNode);

        IssuerSignedJWT issuerSignedJWT = mock(IssuerSignedJWT.class);
        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJWT);
        when(issuerSignedJWT.getPayload()).thenReturn(issuerPayload);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(eq(token), anyString()))
                .thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP)).thenReturn(nonce);
        when(nonceCacheService.consumeNonce(nonce)).thenReturn(challenge);
        doNothing().when(sdJwtVPValidationService).verifySdJwtVP(eq(sdJwtVP), anyString(), eq(nonce));
        doNothing().when(statusListService).updateStatusList(any(), anyString());

        CredentialRevocationResponse response = service.revokeCredential(request, token);

        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertNotNull(response.getRevokedAt());
        assertEquals("User requested revocation", response.getRevocationReason());

        // Core: verify orchestration order and that payload was built from VP (listId, index, INVALID)
        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).updateStatusList(payloadCaptor.capture(), anyString());
        StatusListService.StatusListPayload captured = payloadCaptor.getValue();
        assertEquals("list-1", captured.listId());
        assertEquals(1, captured.status().size());
        assertEquals(1L, captured.status().get(0).index());
        assertEquals("INVALID", captured.status().get(0).status());

        verify(sdJwtVPValidationService).parseAndValidateSdJwtVP(eq(token), anyString());
        verify(sdJwtVPValidationService).extractNonceFromKeyBindingJWT(sdJwtVP);
        verify(nonceCacheService).consumeNonce(nonce);
        verify(sdJwtVPValidationService).verifySdJwtVP(eq(sdJwtVP), anyString(), eq(nonce));
    }

    @Test
    void revokeCredential_parseFails_throws() throws StatusListException {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenThrow(new StatusListException("Invalid token format"));

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "bad-token"));

        assertTrue(exception.getMessage().contains("Invalid token format"));
        verify(statusListService, never()).updateStatusList(any(), anyString());
    }

    @Test
    void revokeCredential_missingNonce_throws401() throws StatusListException {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP)).thenReturn(null);

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "token"));

        assertTrue(exception.getMessage().contains("Invalid or missing nonce"));
        assertEquals(401, exception.getHttpStatus());
        verify(nonceCacheService, never()).consumeNonce(anyString());
        verify(statusListService, never()).updateStatusList(any(), anyString());
    }

    @Test
    void revokeCredential_invalidOrExpiredNonce_throws401() throws StatusListException {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP)).thenReturn("bad-nonce");
        when(nonceCacheService.consumeNonce("bad-nonce")).thenReturn(null);

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "token"));

        assertTrue(exception.getMessage().contains("Invalid, expired, or replayed nonce"));
        assertEquals(401, exception.getHttpStatus());
        verify(statusListService, never()).updateStatusList(any(), anyString());
    }

    @Test
    void revokeCredential_statusListUpdateFails_throws() throws Exception {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);
        request.setRevocationReason("reason");

        String nonce = "nonce-456";
        RevocationChallenge challenge = new RevocationChallenge(nonce, "https://example.com/revoke", 600);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode statusNode = mapper.createObjectNode();
        statusNode.putObject("status_list").put("idx", 1L).put("uri", "https://example.com/statuslists/list-1");
        ObjectNode issuerPayload = mapper.createObjectNode();
        issuerPayload.set("status", statusNode);
        IssuerSignedJWT issuerSignedJWT = mock(IssuerSignedJWT.class);
        when(sdJwtVP.getIssuerSignedJWT()).thenReturn(issuerSignedJWT);
        when(issuerSignedJWT.getPayload()).thenReturn(issuerPayload);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP)).thenReturn(nonce);
        when(nonceCacheService.consumeNonce(nonce)).thenReturn(challenge);
        doNothing().when(sdJwtVPValidationService).verifySdJwtVP(eq(sdJwtVP), anyString(), eq(nonce));
        doThrow(new StatusListException("Server error", 500))
                .when(statusListService)
                .updateStatusList(any(), anyString());

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "token"));

        assertTrue(exception.getMessage().contains("Server error")
                || exception.getMessage().contains("Status list")
                || exception.getMessage().contains("Failed to process"));
        verify(statusListService).updateStatusList(any(), anyString());
    }

    @Test
    void revokeCredential_unexpectedException_wrappedInStatusListException() throws StatusListException {
        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);

        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenThrow(new RuntimeException("Unexpected error"));

        StatusListException exception =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "token"));

        assertTrue(exception.getMessage().contains("Failed to process credential revocation"));
        assertTrue(exception.getMessage().contains("Unexpected error"));
    }

    @Test
    void constructor_withSessionOnly_createsService() {
        CredentialRevocationService s = new CredentialRevocationService(session);
        assertNotNull(s);
    }

    @Test
    void revokeCredential_nullRequest_throwsNPE() {
        assertThrows(NullPointerException.class, () -> service.revokeCredential(null, "token"));
    }

    @Test
    void revokeCredential_nonceProviderNull_throws500() throws Exception {
        when(sdJwtVPValidationService.parseAndValidateSdJwtVP(anyString(), anyString()))
                .thenReturn(sdJwtVP);
        when(sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP)).thenReturn("nonce-1");
        when(session.getProvider(eq(RealmResourceProvider.class), eq(NonceCacheServiceProviderFactory.PROVIDER_ID)))
                .thenReturn(null);

        CredentialRevocationRequest request = new CredentialRevocationRequest();
        request.setRevocationMode(CredentialRevocationRequest.CREDENTIAL_REVOCATION_MODE);

        StatusListException ex =
                assertThrows(StatusListException.class, () -> service.revokeCredential(request, "token"));

        assertTrue(ex.getMessage().contains("Nonce validation service not available"));
        assertEquals(500, ex.getHttpStatus());
        verify(statusListService, never()).updateStatusList(any(), anyString());
    }
}
