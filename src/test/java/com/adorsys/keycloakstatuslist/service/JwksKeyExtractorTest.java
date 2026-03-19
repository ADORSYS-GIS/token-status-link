package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.*;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for JwksKeyExtractor.
 */
@ExtendWith(MockitoExtension.class)
class JwksKeyExtractorTest {

    private JwksKeyExtractor service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        service = new JwksKeyExtractor();
    }

    @Test
    void testExtractPublicKeyFromJwksKey_RSA_TooShort() throws Exception {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");

        // This test data is intentionally invalid for RSA (too short), so we expect an exception
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });

        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_EC_InvalidBase64() throws Exception {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-256");
        keyNode.put("x", "invalid-base64!");
        keyNode.put("y", "AQAB");

        // This test data is intentionally invalid (invalid Base64), so we expect an exception
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });

        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_UnsupportedType() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "UNSUPPORTED");

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });

        assertTrue(exception.getMessage().contains("Unsupported JWKS key type: UNSUPPORTED"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_MissingKty() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");
        // Missing 'kty' field

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });

        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_EC_UnsupportedCurve() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-192"); // Unsupported curve
        keyNode.put("x", "AQAB");
        keyNode.put("y", "AQAB");

        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });

        assertTrue(exception.getMessage().contains("Unsupported EC curve: P-192"));
    }
}
