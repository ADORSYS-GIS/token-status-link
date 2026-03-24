package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.helpers.RSATestUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;

class CryptoIdentityServiceTest extends MockKeycloakTest {

    private CryptoIdentityService service;

    @BeforeEach
    void setUpService() {
        service = new CryptoIdentityService(session);
    }

    @Test
    void getActiveKeyShouldReturnCurrentSigningKey() {
        KeyWrapper key = service.getActiveKey(realm);

        assertNotNull(key);
        assertNotNull(key.getPublicKey());
    }

    @Test
    void getActiveKeyShouldThrowWhenNoActiveSigningKey() {
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256))).thenReturn(null);

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> service.getActiveKey(realm));
        assertTrue(ex.getMessage().contains("No active signing key found"));
    }

    @Test
    void getJwtTokenShouldContainExpectedIssuerClaim() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_TOKEN_ISSUER_PREFIX)).thenReturn("issuer-prefix");
        StatusListConfig config = new StatusListConfig(realm);

        String token = service.getJwtToken(config);

        assertNotNull(token);
        String[] parts = token.split("\\.");
        assertTrue(parts.length >= 2);
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertTrue(payloadJson.contains("\"iss\":\"issuer-prefix::" + TEST_REALM_NAME + "\""));
        assertTrue(payloadJson.contains("\"iat\":"));
        assertTrue(payloadJson.contains("\"exp\":"));
    }

    @Test
    void getRealmKeyDataShouldFallbackToRs256WhenDefaultAlgMissing() throws Exception {
        when(realm.getDefaultSignatureAlgorithm()).thenReturn(null);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.ES256))).thenReturn(null);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256)))
                .thenReturn(RSATestUtils.getRsaKeyWrapper(testJwkResource("/keycloak-active-key-rsa.json")));

        CryptoIdentityService.KeyData keyData = CryptoIdentityService.getRealmKeyData(session, realm);

        assertNotNull(keyData);
        assertNotNull(keyData.jwk());
        assertEquals("RS256", keyData.algorithm());
    }

    @Test
    void getRealmKeyDataShouldSupportEcPublicKey() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(256);
        KeyPair ecPair = ecGen.generateKeyPair();

        KeyWrapper ecKey = new KeyWrapper();
        ecKey.setKid("ec-kid");
        ecKey.setAlgorithm(Algorithm.ES256);
        ecKey.setPublicKey(ecPair.getPublic());

        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.ES256);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.ES256))).thenReturn(ecKey);

        CryptoIdentityService.KeyData keyData = CryptoIdentityService.getRealmKeyData(session, realm);

        assertNotNull(keyData);
        assertNotNull(keyData.jwk());
        assertEquals(Algorithm.ES256, keyData.algorithm());
        assertTrue(ecKey.getPublicKey() instanceof ECPublicKey);
    }

    @Test
    void getRealmKeyDataShouldThrowWhenNoActiveKeyFound() {
        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256))).thenReturn(null);

        StatusListException ex =
                assertThrows(StatusListException.class, () -> CryptoIdentityService.getRealmKeyData(session, realm));
        assertTrue(ex.getMessage().contains("No active signing key found"));
    }

    @Test
    void getRealmKeyDataShouldThrowWhenPublicKeyMissing() {
        KeyWrapper keyWithoutPublicKey = new KeyWrapper();
        keyWithoutPublicKey.setKid("missing-public");
        keyWithoutPublicKey.setAlgorithm(Algorithm.RS256);
        keyWithoutPublicKey.setPublicKey(null);

        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256))).thenReturn(keyWithoutPublicKey);

        StatusListException ex =
                assertThrows(StatusListException.class, () -> CryptoIdentityService.getRealmKeyData(session, realm));
        assertTrue(ex.getMessage().contains("Active key has no public key"));
    }

    @Test
    void getRealmKeyDataShouldThrowForUnsupportedPublicKeyType() {
        PublicKey unsupportedKey = mock(PublicKey.class);

        KeyWrapper unsupported = new KeyWrapper();
        unsupported.setKid("unsupported-kid");
        unsupported.setAlgorithm(Algorithm.RS256);
        unsupported.setPublicKey(unsupportedKey);

        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256))).thenReturn(unsupported);

        StatusListException ex =
                assertThrows(StatusListException.class, () -> CryptoIdentityService.getRealmKeyData(session, realm));
        assertTrue(ex.getMessage().contains("Unsupported key type"));
    }

    @Test
    void getRealmKeyDataShouldWrapUnexpectedExceptions() {
        when(realm.getDefaultSignatureAlgorithm()).thenReturn(Algorithm.RS256);
        when(keyManager.getActiveKey(eq(realm), eq(KeyUse.SIG), eq(Algorithm.RS256)))
                .thenThrow(new RuntimeException("key manager failure"));

        StatusListException ex =
                assertThrows(StatusListException.class, () -> CryptoIdentityService.getRealmKeyData(session, realm));
        assertTrue(ex.getMessage().contains("Failed to retrieve realm public key"));
    }
}
