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
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.util.List;

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
     * Parses the SD-JWT VP token WITHOUT cryptographic verification.
     * This allows extraction of claims (like credential ID and nonce) before full verification.
     * 
     * Use this when you need to extract data before validating nonces or other server-side checks.
     */
    public SdJwtVP parseSdJwtVP(String sdJwtVpString, String requestId) 
            throws StatusListException {
        
        try {
            if (sdJwtVpString == null || sdJwtVpString.trim().isEmpty()) {
                throw new StatusListException("SD-JWT VP token is empty or null");
            }
            
            SdJwtVP sdJwtVP = SdJwtVP.of(sdJwtVpString);
            
            logger.infof("SD-JWT VP parsed successfully. RequestId: %s", requestId);
            
            return sdJwtVP;
            
        } catch (IllegalArgumentException e) {
            logger.errorf("Invalid SD-JWT VP token format. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Malformed VP: Invalid SD-JWT VP token format: " + e.getMessage(), e, 400);
        } catch (Exception e) {
            logger.errorf("Failed to parse SD-JWT VP token. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Malformed VP: Failed to parse SD-JWT VP token: " + e.getMessage(), e, 400);
        }
    }
    
    /**
     * Verifies the SD-JWT VP token's issuer signature and Key Binding JWT using Keycloak's internal key management.
     * This ensures the token was properly issued by the claimed issuer and signed by the holder.
     *      * 
     * @param sdJwtVP the parsed SD-JWT VP token
     * @param requestId the request ID for logging
     * @param credentialId the credential ID being revoked
     * @param expectedNonce the server-generated nonce from the challenge (NOT from client's JWT)
     */
    public void verifySdJwtVPSignature(SdJwtVP sdJwtVP, String requestId, String credentialId, String expectedNonce) throws StatusListException {
        try {
            
            String issuer = extractIssuerFromToken(sdJwtVP);
            if (issuer == null || issuer.trim().isEmpty()) {
                logger.errorf("No issuer found in SD-JWT VP token. RequestId: %s", requestId);
                throw new StatusListException("Token missing required issuer information for verification");
            }
            
            // Use the new approach with internal key management
            List<SignatureVerifierContext> verifyingKeys = jwksService.getSignatureVerifierContexts(sdJwtVP, issuer, requestId);
            
            if (verifyingKeys.isEmpty()) {
                logger.errorf("No valid issuer signature verifier contexts created. RequestId: %s", requestId);
                throw new StatusListException("No public keys available for issuer: " + issuer);
            }
            
            sdJwtVP.verify(
                verifyingKeys,
                getIssuerSignedJwtVerificationOpts(),
                getKeyBindingJwtVerificationOpts(sdJwtVP, requestId, getRevocationEndpointUrl(), credentialId, expectedNonce)
            );
            
            logger.infof("SD-JWT VP signature verification completed successfully with nonce validation. RequestId: %s, Nonce: %s", requestId, expectedNonce);
            
        } catch (VerificationException e) {
            logger.errorf("SD-JWT VP signature verification failed - REJECTING REQUEST. RequestId: %s, Error: %s",
                         requestId, e.getMessage());
            throw new StatusListException("Invalid SD-JWT VP signature: " + e.getMessage(), e, 401);
            
        } catch (Exception e) {
            logger.errorf("SD-JWT VP verification failed - REJECTING REQUEST. RequestId: %s, Error: %s",
                         requestId, e.getMessage());
            throw new StatusListException("SD-JWT VP verification failed: " + e.getMessage(), e, 401);
        }
    }

    /**
     * Verifies that the SD-JWT VP token proves ownership of the specified credential.
     * This checks that the credential ID in the VP matches the requested credential ID.
     * 
     * SECURITY: This method ensures that only the actual credential holder can revoke their credential
     * by verifying the credential ID match. The cryptographic proof is verified separately.
     */
    public void verifyCredentialOwnership(SdJwtVP sdJwtVP, String credentialId, String requestId)
            throws StatusListException {

        String vpCredentialId = extractCredentialIdFromSdJwtVP(sdJwtVP);

        if (vpCredentialId == null || vpCredentialId.isEmpty()) {
            throw new StatusListException("Could not extract credential ID from SD-JWT VP token");
        }

        if (!vpCredentialId.equals(credentialId)) {
            logger.errorf("Credential ownership verification failed. RequestId: %s, Expected: %s, Found: %s",
                         requestId, credentialId, vpCredentialId);
            throw new StatusListException("SD-JWT VP token does not prove ownership of the specified credential");
        }

        logger.infof("Credential ownership verified successfully (credential ID match). RequestId: %s", requestId);
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
     * Extracts the nonce from the Key Binding JWT.
     * This is used for replay attack prevention.
     * 
     * @param sdJwtVP the SD-JWT VP token
     * @return the nonce string from the Key Binding JWT, or null if not present
     */
    public String extractNonceFromKeyBindingJWT(SdJwtVP sdJwtVP) {
        try {
            var kbOpt = sdJwtVP.getKeyBindingJWT();
            if (kbOpt.isEmpty()) {
                logger.debug("No Key Binding JWT present in SD-JWT VP");
                return null;
            }
            
            var payload = kbOpt.get().getPayload();
            if (payload instanceof com.fasterxml.jackson.databind.JsonNode) {
                com.fasterxml.jackson.databind.JsonNode node = (com.fasterxml.jackson.databind.JsonNode) payload;
                com.fasterxml.jackson.databind.JsonNode nonceNode = node.get("nonce");
                if (nonceNode != null && nonceNode.isTextual()) {
                    return nonceNode.asText();
                }
            }
            
            logger.debug("Nonce not found in Key Binding JWT payload");
            return null;
            
        } catch (Exception e) {
            logger.warn("Failed to extract nonce from Key Binding JWT", e);
            return null;
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

        return IssuerSignedJwtVerificationOpts.builder()

                .withValidateNotBeforeClaim(false)
                .withValidateExpirationClaim(false)
                .build();
    }

    /**
     * Creates key binding JWT verification options that enforce presenter verification.
     * This is critical for ensuring the presenter is actually the credential holder.
     * The key binding JWT signature itself provides proof of possession.
     */
    private KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(
            SdJwtVP sdJwtVP, 
            String requestId, 
            String expectedAudience,
            String credentialId,
            String expectedNonce) throws StatusListException {
        try {
            String aud = null;
            Long exp = null;

            // Extract claims from Key Binding JWT (but NOT the nonce - we use server's nonce)
            var kbOpt = sdJwtVP.getKeyBindingJWT();
            if (kbOpt.isPresent()) {
                var payload = kbOpt.get().getPayload();
                if (payload instanceof JsonNode) {
                    JsonNode node = (JsonNode) payload;
                    // NOTE: We do NOT extract nonce from client - we use expectedNonce from server
                    JsonNode audNode = node.get("aud");
                    JsonNode expNode = node.get("exp");
                    
                    if (audNode != null && audNode.isTextual()) {
                        aud = audNode.asText();
                    }
                    if (expNode != null && expNode.isNumber()) {
                        exp = expNode.asLong();
                    }
                }
            }

            if (aud == null) {
                logger.errorf("Missing aud (audience) in Key Binding JWT claims. RequestId: %s", requestId);
                throw new IllegalArgumentException("Missing aud in Key Binding JWT");
            }
            
            // SECURITY FIX: Validate that server provided the expected nonce
            if (expectedNonce == null || expectedNonce.isEmpty()) {
                logger.errorf("Server did not provide expected nonce. RequestId: %s", requestId);
                throw new IllegalArgumentException("Server-generated nonce not provided for Key Binding JWT verification");
            }

            // Validate audience matches the revocation endpoint (with URL normalization)
            String normalizedExpectedAud = normalizeUrl(expectedAudience);
            String normalizedAud = normalizeUrl(aud);
            
            if (!normalizedExpectedAud.equals(normalizedAud)) {
                logger.errorf("Key Binding JWT audience mismatch. Expected: %s (normalized: %s), Got: %s (normalized: %s). RequestId: %s", 
                             expectedAudience, normalizedExpectedAud, aud, normalizedAud, requestId);
                throw new IllegalArgumentException("Key Binding JWT audience does not match revocation endpoint");
            }

            // Validate expiration if present (prevents replay attacks with old tokens)
            if (exp != null) {
                long currentTime = System.currentTimeMillis() / 1000;
                long maxAge = 300; // 5 minutes
                if (currentTime > exp) {
                    logger.errorf("Key Binding JWT has expired. Exp: %d, Current: %d. RequestId: %s", exp, currentTime, requestId);
                    throw new IllegalArgumentException("Key Binding JWT has expired");
                }
                if (exp < (currentTime - maxAge)) {
                    logger.errorf("Key Binding JWT is too old. Exp: %d, Current: %d, MaxAge: %d. RequestId: %s", 
                                 exp, currentTime, maxAge, requestId);
                    throw new IllegalArgumentException("Key Binding JWT is too old (possible replay attack)");
                }
            }

            logger.infof("Key Binding JWT verification options built with server nonce. RequestId: %s, expectedNonce: %s, aud: %s, exp: %s, credentialId: %s", 
                        requestId, expectedNonce, aud, exp != null ? String.valueOf(exp) : "N/A", credentialId);

            // Build verification options with SERVER-GENERATED nonce
            // The Keycloak library will verify that the client's Key Binding JWT contains this exact nonce
            return KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(true)
                    .withAllowedMaxAge(300) // 5 minutes max age
                    .withNonce(expectedNonce)
                    .withAud(expectedAudience) // Required for replay protection
                    .withValidateExpirationClaim(true)
                    .withValidateNotBeforeClaim(false) // Disable nbf validation for Key Binding JWT
                    .build();
        } catch (IllegalArgumentException e) {
            logger.errorf("Failed to build Key Binding verification options due to invalid arguments. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw new StatusListException("Malformed VP: " + e.getMessage(), e, 400);
        } catch (Exception e) {
            logger.errorf("Unexpected error building Key Binding verification options. RequestId: %s, Error: %s", 
                        requestId, e.getMessage());
            throw new StatusListException("Failed to build Key Binding verification options: " + e.getMessage(), e);
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
            return null;
        }
    }

    private String getRevocationEndpointUrl() {
        RealmModel realm = session.getContext().getRealm();
        return Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()) + "/protocol/openid-connect/revoke";
    }
    
    /**
     * Normalizes a URL for comparison by removing default ports, trailing slashes, and converting to lowercase.
     * This helps match URLs that are semantically equivalent but formatted differently.
     * 
     * @param url the URL to normalize
     * @return the normalized URL string
     */
    private String normalizeUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return url;
        }
        
        try {
            URI uri = new URI(url.trim());
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : null;
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : null;
            int port = uri.getPort();
            String path = uri.getPath() != null ? uri.getPath() : "";
            
            // Remove trailing slash from path
            if (path.endsWith("/") && path.length() > 1) {
                path = path.substring(0, path.length() - 1);
            }
            
            // Build normalized URI (remove default ports: 80 for http, 443 for https)
            StringBuilder normalized = new StringBuilder();
            if (scheme != null) {
                normalized.append(scheme).append("://");
            }
            if (host != null) {
                normalized.append(host);
            }
            // Only include port if it's not the default port
            if (port > 0 && !((scheme != null && scheme.equals("http") && port == 80) || 
                              (scheme != null && scheme.equals("https") && port == 443))) {
                normalized.append(":").append(port);
            }
            normalized.append(path);
            
            // Include query and fragment if present
            if (uri.getQuery() != null && !uri.getQuery().isEmpty()) {
                normalized.append("?").append(uri.getQuery());
            }
            if (uri.getFragment() != null && !uri.getFragment().isEmpty()) {
                normalized.append("#").append(uri.getFragment());
            }
            
            return normalized.toString();
        } catch (URISyntaxException e) {
            logger.warnf("Failed to normalize URL: %s, using original", url, e);
            // If normalization fails, return trimmed lowercase version
            return url.trim().toLowerCase();
        }
    }
}
