package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.security.PublicKey;
import java.util.List;
import java.util.ArrayList;

/**
 * Main service for handling JWKS (JSON Web Key Set) operations.
 * Orchestrates the fetching, parsing, and extraction of public keys from issuer JWKS endpoints.
 */
public class JwksService {
    
    private static final Logger logger = Logger.getLogger(JwksService.class);
    
    private final JwksHttpClient httpClient;
    private final JwksParser parser;
    private final JwksKeyExtractor keyExtractor;
    
    public JwksService() {
        this.httpClient = new JwksHttpClient();
        this.parser = new JwksParser();
        this.keyExtractor = new JwksKeyExtractor();
    }
    
    /**
     * Fetches all public keys from the issuer's JWKS endpoint.
     */
    public List<PublicKey> getAllIssuerPublicKeys(SdJwtVP sdJwtVP, String issuer, String requestId) throws StatusListException {
        try {
            String jwksUrl = httpClient.buildJwksUrl(issuer);
            JsonNode jwksJson = httpClient.fetchJwks(jwksUrl, requestId);
            
            List<PublicKey> publicKeys = new ArrayList<>();
            JsonNode keysNode = jwksJson.get("keys");
            
            if (keysNode != null && keysNode.isArray()) {
                logger.debugf("Found %d keys in JWKS for issuer: %s. RequestId: %s", keysNode.size(), issuer, requestId);
                
                for (int i = 0; i < keysNode.size(); i++) {
                    JsonNode jwk = keysNode.get(i);
                    
                    if (parser.isValidKeyForExtraction(jwk)) {
                        try {
                            String kid = parser.getKeyId(jwk);
                            String kty = parser.getKeyType(jwk);
                            
                            logger.debugf("Processing key %d with kid: %s, type: %s. RequestId: %s", i + 1, kid, kty, requestId);
                            
                            PublicKey publicKey = keyExtractor.extractPublicKeyFromJwksKey(jwk);
                            publicKeys.add(publicKey);
                            
                            logger.debugf("Successfully extracted %s public key %d. RequestId: %s", kty, i + 1, requestId);
                            
                        } catch (Exception e) {
                            logger.warnf("Failed to extract public key from key %d. RequestId: %s, Error: %s", i + 1, requestId, e.getMessage());
                        }
                    } else {
                        logger.warnf("Skipping key %d - unsupported type or missing required fields. RequestId: %s", i + 1, requestId);
                    }
                }
            }
            
            logger.infof("Successfully extracted %d public keys from JWKS for issuer: %s. RequestId: %s", publicKeys.size(), issuer, requestId);
            return publicKeys;

        } catch (Exception e) {
            logger.errorf("Failed to fetch or parse issuer JWKS. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Failed to fetch or parse issuer JWKS: " + e.getMessage(), e);
        }
    }
    
    /**
     * Finds a key in the JWKS JSON by its "kid" (Key ID).
     */
    public JsonNode findKeyByKid(JsonNode jwksJson, String kid) {
        return parser.findKeyByKid(jwksJson, kid);
    }
    
    /**
     * Extracts the public key from a JWKS key node.
     */
    public PublicKey extractPublicKeyFromJwksKey(JsonNode keyNode) throws StatusListException {
        return keyExtractor.extractPublicKeyFromJwksKey(keyNode);
    }
} 
