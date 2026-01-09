package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;

import java.security.KeyPairGenerator;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

    private PublicKey rsaPublicKey;

    private RevocationRecordService service;

    @BeforeEach
    void setUp() throws Exception {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.keys()).thenReturn(keyManager);
        lenient().when(realm.getName()).thenReturn("test-realm");
        lenient().when(realm.getDefaultSignatureAlgorithm()).thenReturn("RS256");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaPublicKey = kpg.generateKeyPair().getPublic();

        service = new RevocationRecordService(session);
    }

    @Test
    void testCreateRevocationRecord_Success() throws Exception {
        String credentialId = "test-credential-123";
        String revocationReason = "User requested revocation";
        String requestId = "test-request-id";

        CredentialRevocationRequest request = new CredentialRevocationRequest(
                credentialId, revocationReason
        );

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(rsaPublicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        when(keyWrapper.getKid()).thenReturn("test-kid");

        TokenStatusRecord result = service.createRevocationRecord(request, requestId);

        assertNotNull(result);
        assertEquals(credentialId, result.getCredentialId());
        assertEquals("test-realm", result.getIssuer());

        assertNotNull(result.getPublicKey());
        assertTrue(result.getPublicKey() instanceof JWK);
        assertEquals("test-kid", result.getPublicKey().getKeyId());
        assertEquals("RS256", result.getPublicKey().getAlgorithm());
    }

    @Test
    void testCreateRevocationRecord_WithNullReason() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";

        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, null);

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(rsaPublicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        when(keyWrapper.getKid()).thenReturn("test-kid");

        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        assertEquals("Credential revoked", result.getStatusReason());
    }

    @Test
    void testCreateRevocationRecord_WithEmptyReason() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";

        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(rsaPublicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        when(keyWrapper.getKid()).thenReturn("test-kid");

        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        assertEquals("Credential revoked", result.getStatusReason());
    }

    @Test
    void testCreateRevocationRecord_NoActiveKey() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "reason");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(null);

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });

        assertTrue(exception.getMessage().contains("No active signing key found for realm: test-realm"));
    }

    @Test
    void testCreateRevocationRecord_KeyWithoutPublicKey() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "reason");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(null);

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });

        assertTrue(exception.getMessage().contains("Active key has no public key for realm: test-realm"));
    }

    @Test
    void testCreateRevocationRecord_KeyWithNullAlgorithm() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "reason");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(rsaPublicKey);
        when(keyWrapper.getAlgorithm()).thenReturn(null);

        
        TokenStatusRecord result = service.createRevocationRecord(request, requestId);
        assertEquals("RS256", result.getPublicKey().getAlgorithm());
    }

    @Test
    void testCreateRevocationRecord_KeyManagerException() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "reason");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256")))
                .thenThrow(new RuntimeException("Key manager error"));

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.createRevocationRecord(request, requestId);
        });

        assertTrue(exception.getMessage().contains("Failed to retrieve realm public key"));
    }

    @Test
    void testValidateRevocationReason_TooLongReason() {
        String reason = "a".repeat(256);

        StatusListException exception =
                assertThrows(
                        StatusListException.class,
                        () -> {
                            service.validateRevocationReason(reason);
                        });
        assertTrue(exception.getMessage().contains("Revocation reason exceeds maximum length"));
    }

    @Test
    void testCreateRevocationRecord_VerifyRealmName() throws Exception {
        String credentialId = "test-credential-123";
        String requestId = "test-request-id";
        String realmName = "custom-realm-name";

        when(realm.getName()).thenReturn(realmName);
        CredentialRevocationRequest request = new CredentialRevocationRequest(credentialId, "reason");

        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq("RS256"))).thenReturn(keyWrapper);
        when(keyWrapper.getPublicKey()).thenReturn(rsaPublicKey);
        when(keyWrapper.getAlgorithm()).thenReturn("RS256");

        TokenStatusRecord result = service.createRevocationRecord(request, requestId);

        assertEquals(realmName, result.getIssuer());
    }
}
