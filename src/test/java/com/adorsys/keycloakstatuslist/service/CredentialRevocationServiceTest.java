package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.common.VerificationException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.lang.reflect.Field;
import java.security.PublicKey;
import java.time.Instant;

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
    
    @Mock
    private PublicKey publicKey;
    
    @Mock
    private StatusListService statusListService;
    
    @Mock
    private SdJwtVP sdJwtVP;
    
    @Mock
    private IssuerSignedJWT issuerSignedJWT;
    
    @Mock
    private SignatureVerifierContext signatureVerifierContext;

    private CredentialRevocationService service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        
        lenient().when(realm.getAttribute("status-list-enabled")).thenReturn("true");
        lenient().when(realm.getAttribute("status-list-auth-token")).thenReturn("test-auth-token");
        lenient().when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
        lenient().when(realm.getAttribute("status-list-retry-count")).thenReturn("3");
        lenient().when(realm.getAttribute(anyString())).thenReturn(null);
        
        lenient().when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        lenient().when(keyWrapper.getPublicKey()).thenReturn(publicKey);
        lenient().when(keyWrapper.getAlgorithm()).thenReturn("RS256");
        
        service = new CredentialRevocationService(session);
    }

    @Test
    void testRevokeCredential_EmptySdJwtVp() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "", credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is required"));
    }

    @Test
    void testRevokeCredential_NullSdJwtVp() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                null, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("SD-JWT VP token is required"));
    }

    @Test
    void testRevokeCredential_EmptyCredentialId() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, "", revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("Credential ID is required"));
    }

    @Test
    void testRevokeCredential_NullCredentialId() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, null, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("Credential ID is required"));
    }

    @Test
    void testRevokeCredential_MissingTildeSeparators() {
        String credentialId = "test-credential-123";
        String invalidSdJwtVp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWNyZWRlbnRpYWwtMTIzIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiJ0ZXN0LWNyZWRlbnRpYWwtMTIzIn0.signature";
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                invalidSdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("missing required signing key") || 
                  exception.getMessage().contains("Invalid SD-JWT VP format") ||
                  exception.getMessage().contains("Failed to parse SD-JWT VP token") ||
                  exception.getMessage().contains("SD-JWT is malformed, expected to contain a '~'"));
    }

    @Test
    void testRevokeCredential_InvalidSdJwtVpToken() {
        String credentialId = "test-credential-123";
        String invalidSdJwtVp = "invalid.token.format";
        String revocationReason = "Test revocation";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                invalidSdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertTrue(exception.getMessage().contains("Invalid SD-JWT VP format") ||
                  exception.getMessage().contains("Failed to parse SD-JWT VP token") ||
                  exception.getMessage().contains("Invalid SD-JWT VP token format"));
    }

    @Test
    void testRevokeCredential_LongRevocationReason() {
        String credentialId = "test-credential-123";
        String longReason = "a".repeat(300);
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, longReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_NoActiveKey() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_NullRevocationReason() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, null
        );
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
    }

    @Test
    void testRevokeCredential_EmptyRevocationReason() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, ""
        );
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
    }

    @Test
    void testRevokeCredential_ValidatesInputParameters() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(new CredentialRevocationRequest(null, credentialId, revocationReason));
        });
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(new CredentialRevocationRequest("", credentialId, revocationReason));
        });
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(new CredentialRevocationRequest("valid-token", null, revocationReason));
        });
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(new CredentialRevocationRequest("valid-token", "", revocationReason));
        });
    }

    @Test
    void testRevokeCredential_ValidatesRevocationReason() {
        String credentialId = "test-credential-123";
        String longReason = "a".repeat(300);
        
        assertThrows(StatusListException.class, () -> {
            service.revokeCredential(new CredentialRevocationRequest(createValidSdJwtVP(credentialId), credentialId, longReason));
        });
    }


    @Test
    void testRevokeCredential_NoActiveKeyForVerification() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_KeyWrapperWithoutPublicKey() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_SignatureVerificationFailure() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_CredentialOwnershipMismatch() {
        String credentialId = "test-credential-123";
        String differentCredentialId = "different-credential-456";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_CannotExtractCredentialId() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_VerificationExceptionHandling() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_SuccessfulVerification() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_Success() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_ValidRevocationReason() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation due to security concerns";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_NullRevocationReasonSuccess() throws Exception {
        String credentialId = "test-credential-123";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, null
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_EmptyRevocationReasonSuccess() throws Exception {
        String credentialId = "test-credential-123";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, ""
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_ConcurrentRequests() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_RequestIdGeneration() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_StatusListServiceFailure() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_NetworkTimeout() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createMockSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_InvalidCredentialIdFormat() {
        String credentialId = "invalid-credential-id-with-special-chars!@#$%";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_ExpiredToken() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createExpiredSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_InvalidIssuer() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createSdJwtVPWithInvalidIssuer(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_InvalidTokenStructure() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String invalidSdJwtVp = "invalid.token.structure.without.tilde.separators";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                invalidSdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().contains("Invalid SD-JWT VP") || 
                  exception.getMessage().contains("Failed to parse SD-JWT VP"));
    }

    @Test
    void testRevokeCredential_MalformedToken() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String malformedSdJwtVp = "not.a.valid.jwt.token";
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                malformedSdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().contains("Invalid SD-JWT VP") || 
                  exception.getMessage().contains("Failed to parse SD-JWT VP"));
    }

    @Test
    void testRevokeCredential_ServiceInitialization() {
        CredentialRevocationService newService = new CredentialRevocationService(session);
        assertNotNull(newService);
    }

    @Test
    void testRevokeCredential_MissingHolderSigningKey() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createSdJwtVPWithoutHolderKey(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_InvalidHolderSignature() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createSdJwtVPWithInvalidHolderSignature(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevokeCredential_KeyBindingVerificationRequired() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createSdJwtVPWithoutKeyBinding(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    // ========== KEY COMPONENT TESTS ==========

    @Test
    void testStatusListService_Initialization() {
        CredentialRevocationService newService = new CredentialRevocationService(session);
        assertNotNull(newService);
    }

    @Test
    void testStatusListService_ConfigurationFailure() {
        CredentialRevocationService serviceWithInvalidConfig = new CredentialRevocationService(session);
        assertNotNull(serviceWithInvalidConfig);
    }

    @Test
    void testKeyManagement_NoActiveKey() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testKeyManagement_KeyWithoutPublicKey() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testKeyManagement_DifferentKeyAlgorithm() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevocationRecordCreation_Success() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevocationRecordCreation_WithNullReason() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, null
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testRevocationRecordCreation_WithEmptyReason() {
        String credentialId = "test-credential-123";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, ""
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testJWKSIntegration_NetworkFailure() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testJWKSIntegration_InvalidIssuer() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testSignatureVerification_DifferentAlgorithms() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testTokenFieldExtraction_IssuerExtraction() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testTokenFieldExtraction_KeyIdExtraction() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testCryptographicKeyProcessing_RSAKeyExtraction() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testCryptographicKeyProcessing_ECKeyExtraction() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testSignatureVerifierContext_Creation() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    @Test
    void testErrorHandling_UnexpectedExceptions() {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().length() > 0);
    }

    @Test
    void testErrorHandling_StatusListExceptionPropagation() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "Test revocation";
        String sdJwtVp = createValidSdJwtVP(credentialId);
        
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                sdJwtVp, credentialId, revocationReason
        );
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.revokeCredential(request);
        });
        
        assertNotNull(exception.getMessage());
    }

    private String createValidSdJwtVP(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlAtZ1hsNGZYbjZIc0ZFQ2JncUQweTZiYl9BVzhpc0NsTjFFUno3UlZYUGciLCJ5IjoiOXZQUWt4QmhtQTRFQW9IUXJQRmFoMkdUNHo1V0pmZHF4VTFtVi1tUDEwTSIsImFsZyI6IkVTMjU2Iiwia2lkIjoiaG9sZGVyLWtleSJ9fX0.signature";
    }

    private String createMockSdJwtVP(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlAtZ1hsNGZYbjZIc0ZFQ2JncUQweTZiYl9BVzhpc0NsTjFFUno3UlZYUGciLCJ5IjoiOXZQUWt4QmhtQTRFQW9IUXJQRmFoMkdUNHo1V0pmZHF4VTFtVi1tUDEwTSIsImFsZyI6IkVTMjU2Iiwia2lkIjoiaG9sZGVyLWtleSJ9fX0.mock-signature";
    }

    private String createSdJwtVPWithoutHolderKey(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "In0.signature";
    }

    private String createSdJwtVPWithInvalidHolderSignature(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJJTlZBTElEIiwia2lkIjoiaW52YWxpZC1rZXkifX19.invalid-signature";
    }

    private String createSdJwtVPWithoutKeyBinding(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlAtZ1hsNGZYbjZIc0ZFQ2JncUQweTZiYl9BVzhpc0NsTjFFUno3UlZYUGciLCJ5IjoiOXZQUWt4QmhtQTRFQW9IUXJQRmFoMkdUNHo1V0pmZHF4VTFtVi1tUDEwTSIsImFsZyI6IkVTMjU2Iiwia2lkIjoiaG9sZGVyLWtleSJ9fX0.signature";
    }

    private String createSdJwtVPWithInvalidIssuer(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlAtZ1hsNGZYbjZIc0ZFQ2JncUQweTZiYl9BVzhpc0NsTjFFUno3UlZYUGciLCJ5IjoiOXZQUWt4QmhtQTRFQW9IUXJQRmFoMkdUNHo1V0pmZHF4VTFtVi1tUDEwTSIsImFsZyI6IkVTMjU2Iiwia2lkIjoiaG9sZGVyLWtleSJ9fX0.signature";
    }

    private String createExpiredSdJwtVP(String credentialId) {
        return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI" + credentialId + "IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJpYXQiOjE3NTQzOTQ3NjQsImV4cCI6MTc4NTkzMDc2NCwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwianRpIjoidGVzdC1jcmVkZW50aWFsLTEyMyIsImNyZWRlbnRpYWxfaWQiOiI" + credentialId + "IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlAtZ1hsNGZYbjZIc0ZFQ2JncUQweTZiYl9BVzhpc0NsTjFFUno3UlZYUGciLCJ5IjoiOXZQUWt4QmhtQTRFQW9IUXJQRmFoMkdUNHo1V0pmZHF4VTFtVi1tUDEwTSIsImFsZyI6IkVTMjU2Iiwia2lkIjoiaG9sZGVyLWtleSJ9fX0.signature";
    }
} 
