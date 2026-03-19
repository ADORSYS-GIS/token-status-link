package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for JwksParser.
 */
@ExtendWith(MockitoExtension.class)
class JwksParserTest {

    private JwksParser service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        service = new JwksParser();
    }

    @Test
    void testFindKeyByKid_Success() {
        JsonNode jwksJson = createValidJwksJson();
        String kid = "rsa-key-1";

        JsonNode result = service.findKeyByKid(jwksJson, kid);

        assertNotNull(result);
        assertEquals("RSA", result.get("kty").asText());
        assertEquals(kid, result.get("kid").asText());
    }

    @Test
    void testFindKeyByKid_NotFound() {
        JsonNode jwksJson = createValidJwksJson();
        String kid = "non-existent-key";

        JsonNode result = service.findKeyByKid(jwksJson, kid);

        assertNull(result);
    }

    @Test
    void testFindKeyByKid_NoKeys() {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        jwksJson.putArray("keys");

        JsonNode result = service.findKeyByKid(jwksJson, "test-key");

        assertNull(result);
    }

    @Test
    void testFindKeyByKid_EmptyJwks() {
        ObjectNode jwksJson = objectMapper.createObjectNode();

        JsonNode result = service.findKeyByKid(jwksJson, "test-key");

        assertNull(result);
    }

    @Test
    void testFindKeyByKid_KeysNotArray() {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        jwksJson.put("keys", "not-an-array");

        JsonNode result = service.findKeyByKid(jwksJson, "test-key");

        assertNull(result);
    }

    @Test
    void testFindKeyByKid_KeyWithoutKid() {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        ArrayNode keysArray = jwksJson.putArray("keys");
        ObjectNode keyNode = keysArray.addObject();
        keyNode.put("kty", "RSA");
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");

        JsonNode result = service.findKeyByKid(jwksJson, "test-key");

        assertNull(result);
    }

    @Test
    void testFindKeyByKid_KeyWithNonTextualKid() {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        ArrayNode keysArray = jwksJson.putArray("keys");
        ObjectNode keyNode = keysArray.addObject();
        keyNode.put("kty", "RSA");
        keyNode.put("kid", 123); // Non-textual kid
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");

        JsonNode result = service.findKeyByKid(jwksJson, "test-key");

        assertNull(result);
    }

    @Test
    void testIsValidKeyForExtraction_RSA_Valid() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertTrue(result);
    }

    @Test
    void testIsValidKeyForExtraction_RSA_MissingN() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        keyNode.put("e", "AQAB");
        // Missing 'n' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_RSA_MissingE() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        keyNode.put("n", "AQAB");
        // Missing 'e' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_EC_Valid() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-256");
        keyNode.put("x", "AQAB");
        keyNode.put("y", "AQAB");

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertTrue(result);
    }

    @Test
    void testIsValidKeyForExtraction_EC_MissingCrv() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("x", "AQAB");
        keyNode.put("y", "AQAB");
        // Missing 'crv' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_EC_MissingX() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-256");
        keyNode.put("y", "AQAB");
        // Missing 'x' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_EC_MissingY() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-256");
        keyNode.put("x", "AQAB");
        // Missing 'y' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_UnsupportedType() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "OCT");

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_MissingKty() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");
        // Missing 'kty' parameter

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testIsValidKeyForExtraction_NotObject() {
        JsonNode keyNode = objectMapper.createObjectNode().put("test", "value").get("test");

        boolean result = service.isValidKeyForExtraction(keyNode);

        assertFalse(result);
    }

    @Test
    void testGetKeyType_Valid() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");

        String result = service.getKeyType(keyNode);

        assertEquals("RSA", result);
    }

    @Test
    void testGetKeyType_Missing() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        // No 'kty' field

        String result = service.getKeyType(keyNode);

        assertNull(result);
    }

    @Test
    void testGetKeyId_Valid() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kid", "test-key-123");

        String result = service.getKeyId(keyNode);

        assertEquals("test-key-123", result);
    }

    @Test
    void testGetKeyId_Missing() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        // No 'kid' field

        String result = service.getKeyId(keyNode);

        assertEquals("unknown", result);
    }

    private JsonNode createValidJwksJson() {
        try {
            String jwksResponse = """
                    {
                        "keys": [
                            {
                                "kty": "RSA",
                                "kid": "rsa-key-1",
                                "n": "AQAB",
                                "e": "AQAB"
                            },
                            {
                                "kty": "EC",
                                "kid": "ec-key-1",
                                "crv": "P-256",
                                "x": "AQAB",
                                "y": "AQAB"
                            }
                        ]
                    }
                    """;
            return objectMapper.readTree(jwksResponse);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test JWKS JSON", e);
        }
    }
}
