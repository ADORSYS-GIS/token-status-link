package com.adorsys.keycloakstatuslist.service;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Service responsible for parsing JWKS JSON and finding keys by kid.
 * Handles JWKS structure validation and key searching.
 */
public class JwksParser {
    
    private static final Logger logger = Logger.getLogger(JwksParser.class);

    /**
     * Finds a key in the JWKS JSON by its "kid" (Key ID).
     */
    public JsonNode findKeyByKid(JsonNode jwksJson, String kid) {
        if (jwksJson == null || !jwksJson.has("keys") || !jwksJson.get("keys").isArray()) {
            return null;
        }

        JsonNode keysNode = jwksJson.get("keys");
        for (JsonNode key : keysNode) {
            if (key.has("kid") && kid.equals(key.get("kid").asText())) {
                return key;
            }
        }

        return null;
    }

    /**
     * Validates if a JWKS key node has the required fields for extraction.
     */
    public boolean isValidKeyForExtraction(JsonNode jwk) {
        if (!jwk.isObject() || !jwk.has("kty")) {
            return false;
        }

        String kty = jwk.get("kty").asText();

        if (kty.equals("RSA")) {
            return jwk.has("n") && jwk.has("e");
        } else if (kty.equals("EC")) {
            return jwk.has("crv") && jwk.has("x") && jwk.has("y");
        }

        return false;
    }

    /**
     * Gets the key type from a JWKS key node.
     */
    public String getKeyType(JsonNode jwk) {
        return jwk.has("kty") ? jwk.get("kty").asText() : null;
    }

    /**
     * Gets the key ID from a JWKS key node.
     */
    public String getKeyId(JsonNode jwk) {
        return jwk.has("kid") ? jwk.get("kid").asText() : "unknown";
    }
} 
