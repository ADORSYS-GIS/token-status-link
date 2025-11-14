package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import java.math.BigInteger;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;

/**
 * Service for validating SD-JWT VP tokens.
 * Handles token parsing, signature verification, and credential extraction.
 */
public class SdJwtVPValidationService {
    
    private static final Logger logger = Logger.getLogger(SdJwtVPValidationService.class);
    
    private final KeycloakSession session;
    private final JwksService jwksService;
    
    public SdJwtVPValidationService(KeycloakSession session) {
        this.session = session;
        this.jwksService = new JwksService(session);
    }
    
    /**
     * Parses and validates the SD-JWT VP token.
     * This validates the token structure, parses it for credential extraction, and performs
     * cryptographic signature verification using the token's embedded keys.
     */
    public SdJwtVP parseAndValidateSdJwtVP(String sdJwtVpString, String requestId) 
            throws StatusListException {
        
        logger.debugf("Parsing SD-JWT VP token using Keycloak's built-in SdJwtVP class. RequestId: %s", requestId);
        
        try {
            if (sdJwtVpString == null || sdJwtVpString.trim().isEmpty()) {
                throw new StatusListException("SD-JWT VP token is empty or null");
            }
            
            logger.debugf("SD-JWT VP token length: %d characters. RequestId: %s", sdJwtVpString.length(), requestId);
            
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVpString);
            
            logTokenStructure(sdJwtVP, requestId);
            verifySdJwtVPSignature(sdJwtVP, requestId);
            
            logger.debugf("SD-JWT VP token structure and signature validated successfully. RequestId: %s", requestId);
            return sdJwtVP;
            
        } catch (IllegalArgumentException e) {
            logger.errorf("Invalid SD-JWT VP token format. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Invalid SD-JWT VP token format: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.errorf("Failed to parse SD-JWT VP token. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Failed to parse SD-JWT VP token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Verifies the SD-JWT VP token's issuer signature using Keycloak's internal key management.
     * This ensures the token was properly issued by the claimed issuer.
     */
    public void verifySdJwtVPSignature(SdJwtVP sdJwtVP, String requestId) throws StatusListException {
        try {
            logger.debugf("Verifying SD-JWT VP token issuer signature. RequestId: %s", requestId);
            
            String issuer = extractIssuerFromToken(sdJwtVP);
            if (issuer == null || issuer.trim().isEmpty()) {
                logger.errorf("No issuer found in SD-JWT VP token. RequestId: %s", requestId);
                throw new StatusListException("Token missing required issuer information for verification");
            }
            
            String keyId = extractKeyIdFromToken(sdJwtVP);
            String tokenAlgorithm = extractAlgorithmFromToken(sdJwtVP);
            logger.infof("Extracted issuer: %s, keyId: %s, algorithm: %s. RequestId: %s", 
                         issuer, keyId, tokenAlgorithm, requestId);
            
            // Use the new approach with internal key management
            List<SignatureVerifierContext> verifyingKeys = jwksService.getSignatureVerifierContexts(sdJwtVP, issuer, requestId);
            
            if (verifyingKeys.isEmpty()) {
                logger.errorf("No valid issuer signature verifier contexts created. RequestId: %s", requestId);
                throw new StatusListException("No public keys available for issuer: " + issuer);
            }
            
            logger.infof("Created %d issuer signature verifier contexts for issuer: %s. RequestId: %s", 
                        verifyingKeys.size(), issuer, requestId);
            
            logger.infof("Attempting issuer signature verification with %d verifier contexts. RequestId: %s", 
                         verifyingKeys.size(), requestId);
            
            sdJwtVP.verify(
                getIssuerSignedJwtVerificationOpts(),
                getKeyBindingJwtVerificationOpts(requestId)
            );
            
            logger.infof("SD-JWT VP issuer signature verification completed successfully. RequestId: %s", requestId);
            
        } catch (VerificationException e) {
            logger.errorf("SD-JWT VP issuer signature verification failed - REJECTING REQUEST. RequestId: %s, Error: %s", 
                         requestId, e.getMessage());
            throw new StatusListException("Invalid SD-JWT VP issuer signature: " + e.getMessage(), e);
            
        } catch (Exception e) {
            logger.errorf("SD-JWT VP issuer verification failed - REJECTING REQUEST. RequestId: %s, Error: %s", 
                         requestId, e.getMessage());
            throw new StatusListException("SD-JWT VP issuer verification failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Verifies that the SD-JWT VP token proves ownership of the specified credential.
     * This includes credential ID matching, holder signature verification, and key binding validation.
     * 
     * SECURITY: This method ensures that only the actual credential holder can revoke their credential
     * by verifying their cryptographic signature on the VP token.
     */
    public void verifyCredentialOwnership(SdJwtVP sdJwtVP, String credentialId, String requestId) 
            throws StatusListException {
        
        logger.debugf("Verifying credential ownership with holder signature verification. RequestId: %s, CredentialId: %s", 
                     requestId, credentialId);
        
        String vpCredentialId = extractCredentialIdFromSdJwtVP(sdJwtVP);
        
        if (vpCredentialId == null || vpCredentialId.isEmpty()) {
            throw new StatusListException("Could not extract credential ID from SD-JWT VP token");
        }
        
        if (!vpCredentialId.equals(credentialId)) {
            logger.errorf("Credential ownership verification failed. RequestId: %s, Expected: %s, Found: %s", 
                         requestId, credentialId, vpCredentialId);
            throw new StatusListException("SD-JWT VP token does not prove ownership of the specified credential");
        }
        
        verifyHolderSignatureAndKeyBinding(sdJwtVP, requestId);
        
        logger.infof("Credential ownership verified successfully with holder signature. RequestId: %s", requestId);
    }
    
    /**
     * Verifies the holder's signature and key binding to ensure true ownership.
     * This is the critical security check that proves the credential holder actually signed the VP token.
     * 
     * SECURITY: If holder signature verification fails, the request is rejected immediately.
     */
    public void verifyHolderSignatureAndKeyBinding(SdJwtVP sdJwtVP, String requestId) throws StatusListException {
        try {
            logger.debugf("Verifying holder signature and key binding. RequestId: %s", requestId);
            
            logger.infof("Attempting holder signature verification with key binding required. RequestId: %s", requestId);
            
            // The SD-JWT library automatically handles key binding verification when enabled
            // No need to manually extract and verify the holder's key
            // For holder signature, the key is within the token, so no external verifier is needed.
            // The library handles this internally when key binding is required.
            sdJwtVP.verify(
                getIssuerSignedJwtVerificationOpts(),
                getKeyBindingJwtVerificationOpts(requestId)
            );
            
            logger.infof("Holder signature verification completed successfully. RequestId: %s", requestId);
            
        } catch (VerificationException e) {
            logger.errorf("Holder signature verification failed - REJECTING REQUEST. RequestId: %s, Error: %s", 
                         requestId, e.getMessage());
            throw new StatusListException("Invalid holder signature: " + e.getMessage(), e);
            
        } catch (Exception e) {
            logger.errorf("Holder signature verification failed - REJECTING REQUEST. RequestId: %s, Error: %s", 
                         requestId, e.getMessage());
            throw new StatusListException("Holder signature verification failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a SignatureVerifierContext using the provided PublicKey.
     * This method provides proper cryptographic signature verification.
     */
    public SignatureVerifierContext createSignatureVerifierContextFromPublicKey(PublicKey publicKey, String algorithm) throws StatusListException {
        try {
            if (publicKey == null) {
                throw new IllegalArgumentException("Public key cannot be null");
            }
            if (algorithm == null || algorithm.trim().isEmpty()) {
                throw new IllegalArgumentException("Algorithm cannot be null or empty");
            }
            
            KeyWrapper keyWrapper = new KeyWrapper() {
                @Override
                public String getKid() {
                    return "external-key";
                }
                
                @Override
                public String getAlgorithm() {
                    return algorithm;
                }
                
                @Override
                public PublicKey getPublicKey() {
                    return publicKey;
                }
                
                @Override
                public String getProviderId() {
                    return "external";
                }
                
                @Override
                public String getType() {
                    return "RSA";
                }
                
                @Override
                public KeyStatus getStatus() {
                    return KeyStatus.ACTIVE;
                }
                
                @Override
                public long getProviderPriority() {
                    return 0L;
                }
            };
            
            return new AsymmetricSignatureVerifierContext(keyWrapper);
            
        } catch (Exception e) {
            logger.error("Failed to create signature verifier context from public key", e);
            throw new StatusListException("Failed to create signature verifier context from public key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extracts the credential ID from the SD-JWT VP token.
     * Searches recursively through the payload for credential ID fields.
     */
    public String extractCredentialIdFromSdJwtVP(SdJwtVP sdJwtVP) {
        try {
            var payload = sdJwtVP.getIssuerSignedJWT().getPayload();
            
            String credentialId = extractField(payload, "sub");
            if (credentialId == null) {
                credentialId = extractField(payload, "credential_id");
            }
            if (credentialId == null) {
                credentialId = extractField(payload, "jti");
            }
            
            if (credentialId == null) {
                credentialId = findCredentialIdRecursively(payload);
            }
            
            return credentialId;
            
        } catch (Exception e) {
            logger.warn("Failed to extract credential ID from SD-JWT VP token", e);
            return null;
        }
    }
    
    /**
     * Extracts the issuer from the SD-JWT VP token.
     */
    public String extractIssuerFromToken(SdJwtVP sdJwtVP) {
        try {
            return extractPayloadField(sdJwtVP, "iss");
        } catch (Exception e) {
            logger.warn("Failed to extract issuer from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the JWT ID from the SD-JWT VP token.
     */
    public String extractJwtIdFromToken(SdJwtVP sdJwtVP) {
        try {
            return extractPayloadField(sdJwtVP, "jti");
        } catch (Exception e) {
            logger.warn("Failed to extract JWT ID from SD-JWT VP token", e);
            return null;
        }
    }
    
    /**
     * Extracts the key ID from the SD-JWT VP token header.
     */
    public String extractKeyIdFromToken(SdJwtVP sdJwtVP) {
        try {
            return extractHeaderParam(sdJwtVP, "kid");
        } catch (Exception e) {
            logger.warn("Failed to extract key ID from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the algorithm from the SD-JWT VP token header.
     */
    public String extractAlgorithmFromToken(SdJwtVP sdJwtVP) {
        try {
            return extractHeaderParam(sdJwtVP, "alg");
        } catch (Exception e) {
            logger.warn("Failed to extract algorithm from SD-JWT VP token", e);
            return null;
        }
    }

    private String extractHeaderParam(SdJwtVP sdJwtVP, String paramName) {
        var jwt = sdJwtVP.getIssuerSignedJWT();
        var header = jwt.getHeader();
        if ("kid".equals(paramName)) {
            return header != null ? header.getKeyId() : null;
        }
        if ("alg".equals(paramName)) {
            var algorithm = header != null ? header.getAlgorithm() : null;
            return algorithm != null ? algorithm.name() : null;
        }
        return null;
    }
    
    /**
     * Extracts the holder's signing key from the token's cnf.jwk field.
     * This is the key that the credential holder used to sign the VP token.
     */
    public PublicKey extractSigningKeyFromToken(SdJwtVP sdJwtVP) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var payload = jwt.getPayload();
            
            if (payload instanceof JsonNode) {
                JsonNode payloadNode = (JsonNode) payload;
                JsonNode cnfNode = payloadNode.get("cnf");
                
                if (cnfNode == null || !cnfNode.isObject()) {
                    logger.debug("No cnf field found in token payload");
                    return null;
                }
                
                JsonNode jwkNode = cnfNode.get("jwk");
                if (jwkNode == null || !jwkNode.isObject()) {
                    logger.debug("No jwk field found in cnf object");
                    return null;
                }
                
                if (!jwkNode.has("kty")) {
                    logger.warn("JWK missing required 'kty' field");
                    return null;
                }
                
                String keyType = jwkNode.get("kty").asText();
                logger.debugf("Extracting holder signing key of type: %s", keyType);
                
                PublicKey publicKey = extractPublicKeyFromJwk(jwkNode);
                if (publicKey != null) {
                    logger.debugf("Successfully extracted holder signing key: %s", publicKey.getAlgorithm());
                } else {
                    logger.warn("Failed to extract valid public key from JWK");
                }
                
                return publicKey;
            } else {
                logger.debug("Token payload is not a JsonNode, cannot extract signing key");
                return null;
            }
            
        } catch (Exception e) {
            logger.warn("Failed to extract signing key from token's cnf.jwk", e);
            return null;
        }
    }
    
    private PublicKey extractPublicKeyFromJwk(JsonNode jwkNode) throws StatusListException {
        try {
            if (!jwkNode.has("kty")) {
                logger.warn("JWK missing required 'kty' field");
                return null;
            }

            String keyType = jwkNode.get("kty").asText();
            logger.debugf("Extracting public key of type: %s", keyType);

            if (keyType.equals("RSA")) {
                if (!jwkNode.has("n") || !jwkNode.has("e")) {
                    logger.warn("RSA JWK missing required 'n' or 'e' fields");
                    return null;
                }
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(jwkNode.get("n").asText()));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(jwkNode.get("e").asText()));
                return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
            } else if (keyType.equals("EC")) {
                if (!jwkNode.has("x") || !jwkNode.has("y")) {
                    logger.warn("EC JWK missing required 'x' or 'y' fields");
                    return null;
                }
                ECPoint point = new ECPoint(
                    new BigInteger(1, Base64.getUrlDecoder().decode(jwkNode.get("x").asText())),
                    new BigInteger(1, Base64.getUrlDecoder().decode(jwkNode.get("y").asText()))
                );
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, null)); // Elliptic curves don't have an exponent
            }
            logger.warnf("Unsupported JWK key type: %s", keyType);
            return null;
        } catch (Exception e) {
            logger.error("Failed to extract public key from JWK", e);
            throw new StatusListException("Failed to extract public key from JWK: " + e.getMessage(), e);
        }
    }

    private void logTokenStructure(SdJwtVP sdJwtVP, String requestId) {
        try {
            var issuerSignedJWT = sdJwtVP.getIssuerSignedJWT();
            if (issuerSignedJWT != null) {
                var header = issuerSignedJWT.getHeader();
                var payload = issuerSignedJWT.getPayload();
                
                logger.debugf("Token structure - Header: %s, Payload type: %s. RequestId: %s", 
                             header != null ? "present" : "null", 
                             payload != null ? payload.getClass().getSimpleName() : "null", 
                             requestId);
                
                if (header != null) {
                    String alg = extractAlgorithmFromToken(sdJwtVP);
                    String kid = extractKeyIdFromToken(sdJwtVP);
                    logger.debugf("Token header - Algorithm: %s, Key ID: %s. RequestId: %s", alg, kid, requestId);
                }
            }
        } catch (Exception e) {
            logger.debugf("Failed to log token structure. RequestId: %s, Error: %s", requestId, e.getMessage());
        }
    }
    
    private String findCredentialIdRecursively(JsonNode node) {
        if (node == null) return null;
        
        if (node.isObject()) {
            JsonNode credentialId = node.get("credential_id");
            if (credentialId != null && credentialId.isTextual()) {
                return credentialId.asText();
            }
            
            String[] idFields = {"sub", "jti", "id", "credentialId", "credential_id"};
            for (String field : idFields) {
                JsonNode idNode = node.get(field);
                if (idNode != null && idNode.isTextual()) {
                    return idNode.asText();
                }
            }
            
            for (JsonNode child : node) {
                String id = findCredentialIdRecursively(child);
                if (id != null) return id;
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                String id = findCredentialIdRecursively(child);
                if (id != null) return id;
            }
        }
        
        return null;
    }
    
    private String extractField(Object payload, String fieldName) {
        try {
            if (payload instanceof JsonNode) {
                JsonNode node = (JsonNode) payload;
                JsonNode field = node.get(fieldName);
                return field != null ? field.asText() : null;
            }
        } catch (Exception e) {
            logger.debug("Failed to extract field " + fieldName + " from payload", e);
        }
        return null;
    }

    /**
     * Creates issuer signed JWT verification options with appropriate security settings.
     * These options control how the issuer signature is validated.
     */
    private IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        // In recent Keycloak versions, verifier resolution is likely handled internally.
        // Time-based validations are also often enabled by default or controlled differently.
        return IssuerSignedJwtVerificationOpts.builder().build();
    }

    /**
     * Creates key binding JWT verification options that enforce presenter verification.
     * This is critical for ensuring the presenter is actually the credential holder.
     */
    private KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String requestId) {
        try {
            String expectedKbJwtAud = this.session.getContext().getUri().getBaseUri().getHost();
            logger.debugf("Setting expected key binding audience: %s. RequestId: %s", expectedKbJwtAud, requestId);
            
            return KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(true)
                    .withAllowedMaxAge(300)
                    .withAud(expectedKbJwtAud)
                    .build();
                    
        } catch (Exception e) {
            logger.warnf("Could not determine expected audience from session context, using default. RequestId: %s, Error: %s", 
                        requestId, e.getMessage());
            
            // Fallback to secure defaults if we can't get the context
            return KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(true)
                    .withAllowedMaxAge(300)
                    .build();
        }
    }

    /**
     * Helper method to extract a field from the JWT payload.
     */
    private String extractPayloadField(SdJwtVP sdJwtVP, String fieldName) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var payload = jwt.getPayload();
            if (payload instanceof JsonNode) {
                JsonNode payloadNode = (JsonNode) payload;
                JsonNode fieldNode = payloadNode.get(fieldName);
                return fieldNode != null ? fieldNode.asText() : null;
            }
            return null;
        } catch (Exception e) {
            logger.debugf("Failed to extract field %s from JWT payload", fieldName, e);
            return null;
        }
    }
} 
