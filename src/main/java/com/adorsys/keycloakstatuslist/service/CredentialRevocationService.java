package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.common.VerificationException;

import java.time.Instant;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.security.PublicKey;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import java.math.BigInteger;
import java.util.Base64;

/**
 * Service for handling credential revocation requests.
 * Validates SD-JWT VP tokens and processes credential revocations.
 */
public class CredentialRevocationService {
    
    private static final Logger logger = Logger.getLogger(CredentialRevocationService.class);
    
    private final KeycloakSession session;
    private StatusListService statusListService;

    public CredentialRevocationService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Gets or creates the StatusListService instance.
     */
    private StatusListService getStatusListService() {
        if (statusListService == null) {
            RealmModel realm = session.getContext().getRealm();
            StatusListConfig config = new StatusListConfig(realm);
            this.statusListService = new StatusListService(
                    config.getServerUrl(),
                    config.getAuthToken(),
                    config.getConnectTimeout(),
                    config.getReadTimeout(),
                    config.getRetryCount()
            );
        }
        return statusListService;
    }

    /**
     * Processes a credential revocation request.
     * 
     * @param request the revocation request containing SD-JWT VP token
     * @return response indicating success or failure of the revocation
     * @throws StatusListException if revocation processing fails
     */
    public CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request) 
            throws StatusListException {
        
        String requestId = UUID.randomUUID().toString();
        
        validateRevocationRequest(request);
        
        logger.infof("Processing credential revocation request. RequestId: %s, CredentialId: %s", 
                    requestId, request.getCredentialId());

        try {
            SdJwtVP sdJwtVP = parseAndValidateSdJwtVP(request.getSdJwtVp(), requestId);
            
            verifyCredentialOwnership(sdJwtVP, request.getCredentialId(), requestId);
            
            TokenStatusRecord revocationRecord = createRevocationRecord(request, requestId);
            
            getStatusListService().publishRecord(revocationRecord);
            
            Instant revokedAt = Instant.now();
            logger.infof("Successfully revoked credential. RequestId: %s, CredentialId: %s, RevokedAt: %s", 
                        requestId, request.getCredentialId(), revokedAt);
            
            return CredentialRevocationResponse.success(
                    request.getCredentialId(),
                    revokedAt,
                    request.getRevocationReason()
            );
            
        } catch (StatusListException e) {
            logger.errorf("Status list operation failed. RequestId: %s, Error: %s", requestId, e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.errorf("Unexpected error during credential revocation. RequestId: %s, Error: %s", 
                         requestId, e.getMessage(), e);
            throw new StatusListException("Failed to process credential revocation: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the revocation request parameters.
     */
    private void validateRevocationRequest(CredentialRevocationRequest request) throws StatusListException {
        if (request == null) {
            throw new StatusListException("Revocation request cannot be null");
        }
        
        if (request.getSdJwtVp() == null || request.getSdJwtVp().trim().isEmpty()) {
            throw new StatusListException("SD-JWT VP token is required");
        }
        
        if (request.getCredentialId() == null || request.getCredentialId().trim().isEmpty()) {
            throw new StatusListException("Credential ID is required");
        }
    }

    /**
     * Validates the revocation reason.
     */
    private void validateRevocationReason(String reason) throws StatusListException {
        if (reason != null && reason.length() > 255) {
            throw new StatusListException("Revocation reason exceeds maximum length of 255 characters");
        }
    }

    /**
     * Parses and validates the SD-JWT VP token using Keycloak's built-in SdJwtVP class.
     * This validates the token structure, parses it for credential extraction, and performs
     * cryptographic signature verification using the token's embedded keys.
     */
    private SdJwtVP parseAndValidateSdJwtVP(String sdJwtVpString, String requestId) 
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
     * Logs token structure information for debugging purposes.
     */
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

    /**
     * Verifies the SD-JWT VP token's issuer signature using the issuer's public key from their JWKS endpoint.
     * This ensures the token was properly issued by the claimed issuer.
     */
    private void verifySdJwtVPSignature(SdJwtVP sdJwtVP, String requestId) throws StatusListException {
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
            
            List<PublicKey> issuerPublicKeys = getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            if (issuerPublicKeys.isEmpty()) {
                logger.errorf("No public keys found for issuer: %s. RequestId: %s", issuer, requestId);
                throw new StatusListException("No public keys available for issuer: " + issuer);
            }
            
            List<SignatureVerifierContext> verifyingKeys = new ArrayList<>();
            for (int i = 0; i < issuerPublicKeys.size(); i++) {
                PublicKey publicKey = issuerPublicKeys.get(i);
                try {
                    logger.debugf("Processing issuer public key %d: %s. RequestId: %s", i + 1, publicKey.getAlgorithm(), requestId);
                    
                    String[] algorithms = {"RS256", "ES256", "PS256"};
                    for (String algorithm : algorithms) {
                        try {
                            SignatureVerifierContext verifierContext = createSignatureVerifierContextFromPublicKey(publicKey, algorithm);
                            verifyingKeys.add(verifierContext);
                            logger.debugf("Added issuer verifier context for key %d with algorithm: %s. RequestId: %s", i + 1, algorithm, requestId);
                        } catch (Exception e) {
                            logger.debugf("Failed to create issuer verifier context for key %d with algorithm: %s. RequestId: %s, Error: %s", 
                                         i + 1, algorithm, requestId, e.getMessage());
                        }
                    }
                } catch (Exception e) {
                    logger.warnf("Failed to create issuer verifier context for public key %d. RequestId: %s, Error: %s", 
                                i + 1, requestId, e.getMessage());
                }
            }
            
            if (verifyingKeys.isEmpty()) {
                logger.errorf("No valid issuer signature verifier contexts created. RequestId: %s", requestId);
                throw new StatusListException("Failed to create issuer signature verifier contexts for issuer: " + issuer);
            }
            
            logger.infof("Created %d issuer signature verifier contexts for issuer: %s. RequestId: %s", 
                        verifyingKeys.size(), issuer, requestId);
            
            IssuerSignedJwtVerificationOpts issuerSignedJwtVerificationOpts = 
                new IssuerSignedJwtVerificationOpts(false, false, true);
            
            KeyBindingJwtVerificationOpts keyBindingOpts = new KeyBindingJwtVerificationOpts(
                false,
                0,
                null,
                null,
                false,
                false
            );
            
            logger.infof("Attempting issuer signature verification with %d verifier contexts. RequestId: %s", 
                         verifyingKeys.size(), requestId);
            
            sdJwtVP.verify(
                verifyingKeys,
                issuerSignedJwtVerificationOpts,
                keyBindingOpts
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
     * Extracts credential ID from the payload node.
     */
    private String extractCredentialIdFromPayload(JsonNode payloadNode) {
        String[] idFields = {"sub", "credential_id", "jti", "id"};
        for (String field : idFields) {
            if (payloadNode.has(field)) {
                JsonNode idNode = payloadNode.get(field);
                if (idNode != null && idNode.isTextual()) {
                    String id = idNode.asText();
                    if (id != null && !id.trim().isEmpty()) {
                        return id;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Verifies that the SD-JWT VP token proves ownership of the specified credential.
     * This includes credential ID matching, holder signature verification, and key binding validation.
     * 
     * SECURITY: This method ensures that only the actual credential holder can revoke their credential
     * by verifying their cryptographic signature on the VP token.
     */
    private void verifyCredentialOwnership(SdJwtVP sdJwtVP, String credentialId, String requestId) 
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
    private void verifyHolderSignatureAndKeyBinding(SdJwtVP sdJwtVP, String requestId) throws StatusListException {
        try {
            logger.debugf("Verifying holder signature and key binding. RequestId: %s", requestId);
            
            PublicKey holderPublicKey = extractSigningKeyFromToken(sdJwtVP);
            if (holderPublicKey == null) {
                logger.errorf("No holder signing key found in VP token. RequestId: %s", requestId);
                throw new StatusListException("VP token missing holder's signing key (cnf.jwk) - cannot verify ownership");
            }
            
            logger.debugf("Extracted holder public key: %s. RequestId: %s", holderPublicKey.getAlgorithm(), requestId);
            
            SignatureVerifierContext holderVerifier = createSignatureVerifierContextFromPublicKey(holderPublicKey, "RS256");
            
            IssuerSignedJwtVerificationOpts issuerSignedJwtVerificationOpts = 
                new IssuerSignedJwtVerificationOpts(false, false, true);
            
            KeyBindingJwtVerificationOpts keyBindingOpts = new KeyBindingJwtVerificationOpts(
                true,
                300,
                null,
                null,
                false,
                false
            );
            
            logger.infof("Attempting holder signature verification with key binding required. RequestId: %s", requestId);
            
            sdJwtVP.verify(
                List.of(holderVerifier),
                issuerSignedJwtVerificationOpts,
                keyBindingOpts
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
     * Creates a SignatureVerifierContext using the provided KeyWrapper.
     * This method provides proper cryptographic signature verification.
     */
    private SignatureVerifierContext createSignatureVerifierContext(KeyWrapper keyWrapper) throws StatusListException {
        try {
            if (keyWrapper.getPublicKey() == null) {
                throw new StatusListException("Key wrapper has no public key available for verification");
            }
            
            return new AsymmetricSignatureVerifierContext(keyWrapper);
            
        } catch (Exception e) {
            logger.error("Failed to create signature verifier context", e);
            throw new StatusListException("Failed to create signature verifier context: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a SignatureVerifierContext using the provided PublicKey.
     * This method provides proper cryptographic signature verification.
     */
    private SignatureVerifierContext createSignatureVerifierContextFromPublicKey(PublicKey publicKey, String algorithm) throws StatusListException {
        try {
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
    private String extractCredentialIdFromSdJwtVP(SdJwtVP sdJwtVP) {
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
     * Recursively searches through JSON payload for credential ID fields.
     */
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

    /**
     * Helper method to extract a field from JSON payload.
     */
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
     * Extracts the issuer from the SD-JWT VP token.
     */
    private String extractIssuerFromToken(SdJwtVP sdJwtVP) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var payload = jwt.getPayload();
            if (payload instanceof JsonNode) {
                JsonNode payloadNode = (JsonNode) payload;
                JsonNode issuerNode = payloadNode.get("iss");
                return issuerNode != null ? issuerNode.asText() : null;
            }
            return null;
        } catch (Exception e) {
            logger.warn("Failed to extract issuer from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the JWT ID from the SD-JWT VP token.
     */
    private String extractJwtIdFromToken(SdJwtVP sdJwtVP) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var payload = jwt.getPayload();
            if (payload instanceof JsonNode) {
                JsonNode payloadNode = (JsonNode) payload;
                JsonNode jtiNode = payloadNode.get("jti");
                return jtiNode != null ? jtiNode.asText() : null;
            }
            return null;
        } catch (Exception e) {
            logger.warn("Failed to extract JWT ID from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the key ID from the SD-JWT VP token header.
     */
    private String extractKeyIdFromToken(SdJwtVP sdJwtVP) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var header = jwt.getHeader();
            return header.getKeyId();
        } catch (Exception e) {
            logger.warn("Failed to extract key ID from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Extracts the algorithm from the SD-JWT VP token header.
     */
    private String extractAlgorithmFromToken(SdJwtVP sdJwtVP) {
        try {
            var jwt = sdJwtVP.getIssuerSignedJWT();
            var header = jwt.getHeader();
            var algorithm = header.getAlgorithm();
            return algorithm != null ? algorithm.name() : null;
        } catch (Exception e) {
            logger.warn("Failed to extract algorithm from SD-JWT VP token", e);
            return null;
        }
    }

    /**
     * Fetches the public key from the issuer's JWKS endpoint.
     */
    private List<PublicKey> getAllIssuerPublicKeys(SdJwtVP sdJwtVP, String issuer, String requestId) throws StatusListException {
        try {
            String jwksUrl;
            if (issuer.contains("/realms/")) {
                jwksUrl = issuer + "/protocol/openid-connect/certs";
            } else {
                jwksUrl = issuer.endsWith("/") ? issuer + ".well-known/jwks.json" : issuer + "/.well-known/jwks.json";
            }
            
            logger.debugf("Fetching JWKS from: %s. RequestId: %s", jwksUrl, requestId);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(jwksUrl))
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();

            if (statusCode >= 400) {
                logger.errorf("Failed to fetch JWKS from %s. Status: %d, Body: %s. RequestId: %s", 
                             jwksUrl, statusCode, response.body(), requestId);
                throw new StatusListException("Failed to fetch JWKS from issuer: " + issuer + " (Status: " + statusCode + ")");
            }

            JsonNode jwksJson = new ObjectMapper().readTree(response.body());
            if (jwksJson == null || !jwksJson.isObject()) {
                logger.errorf("Invalid JWKS format from %s. RequestId: %s", jwksUrl, requestId);
                throw new StatusListException("Invalid JWKS format from issuer: " + issuer);
            }

            List<PublicKey> publicKeys = new ArrayList<>();
            JsonNode keysNode = jwksJson.get("keys");
            if (keysNode != null && keysNode.isArray()) {
                logger.debugf("Found %d keys in JWKS for issuer: %s. RequestId: %s", keysNode.size(), issuer, requestId);
                for (int i = 0; i < keysNode.size(); i++) {
                    JsonNode jwk = keysNode.get(i);
                    if (jwk.isObject() && jwk.has("kty")) {
                        String kty = jwk.get("kty").asText();
                        try {
                            String kid = jwk.has("kid") ? jwk.get("kid").asText() : "unknown";
                            logger.debugf("Processing key %d with kid: %s, type: %s. RequestId: %s", i + 1, kid, kty, requestId);
                            
                            if (kty.equals("RSA") && jwk.has("n") && jwk.has("e")) {
                                PublicKey publicKey = extractPublicKeyFromJwksKey(jwk);
                                publicKeys.add(publicKey);
                                logger.debugf("Successfully extracted RSA public key %d. RequestId: %s", i + 1, requestId);
                            } else if (kty.equals("EC") && jwk.has("crv") && jwk.has("x") && jwk.has("y")) {
                                PublicKey publicKey = extractPublicKeyFromJwksKey(jwk);
                                publicKeys.add(publicKey);
                                logger.debugf("Successfully extracted EC public key %d. RequestId: %s", i + 1, requestId);
                            } else {
                                logger.warnf("Skipping key %d - unsupported type or missing required fields. RequestId: %s", i + 1, requestId);
                            }
                        } catch (Exception e) {
                            logger.warnf("Failed to extract public key from key %d. RequestId: %s, Error: %s", i + 1, requestId, e.getMessage());
                        }
                    } else {
                        logger.warnf("Skipping key %d - missing kty field. RequestId: %s", i + 1, requestId);
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
    private JsonNode findKeyByKid(JsonNode jwksJson, String kid) {
        if (jwksJson.isObject()) {
            JsonNode keysNode = jwksJson.get("keys");
            if (keysNode != null && keysNode.isArray()) {
                logger.debugf("Searching for key with kid: %s in JWKS with %d keys", kid, keysNode.size());
                for (JsonNode jwk : keysNode) {
                    if (jwk.isObject() && jwk.has("kid") && jwk.get("kid").isTextual()) {
                        String currentKid = jwk.get("kid").asText();
                        logger.debugf("Checking key with kid: %s", currentKid);
                        if (currentKid.equals(kid)) {
                            logger.debugf("Found matching key with kid: %s", currentKid);
                            return jwk;
                        }
                    }
                }
                logger.warnf("No key found with kid: %s in JWKS", kid);
            }
        }
        return null;
    }

    /**
     * Extracts the public key from a JWKS key node.
     */
    private PublicKey extractPublicKeyFromJwksKey(JsonNode keyNode) throws StatusListException {
        try {
            String kty = keyNode.get("kty").asText();
            
            if (kty.equals("RSA")) {
                return extractRsaPublicKey(keyNode);
            } else if (kty.equals("EC")) {
                return extractEcPublicKey(keyNode);
            } else {
                throw new StatusListException("Unsupported JWKS key type: " + kty);
            }
            
        } catch (Exception e) {
            logger.errorf("Failed to extract public key from JWKS key node. Error: %s", e.getMessage());
            throw new StatusListException("Failed to extract public key from JWKS key node: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts an RSA public key from a JWKS key node.
     */
    private PublicKey extractRsaPublicKey(JsonNode keyNode) throws Exception {
        String n = keyNode.get("n").asText();
        String e = keyNode.get("e").asText();

        if (n == null || e == null) {
            throw new StatusListException("Missing required RSA JWKS key parameters (n, e)");
        }

        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    /**
     * Extracts an EC public key from a JWKS key node.
     */
    private PublicKey extractEcPublicKey(JsonNode keyNode) throws Exception {
        String crv = keyNode.get("crv").asText();
        String x = keyNode.get("x").asText();
        String y = keyNode.get("y").asText();

        if (crv == null || x == null || y == null) {
            throw new StatusListException("Missing required EC JWKS key parameters (crv, x, y)");
        }

        BigInteger xCoord = new BigInteger(1, Base64.getUrlDecoder().decode(x));
        BigInteger yCoord = new BigInteger(1, Base64.getUrlDecoder().decode(y));

        ECPoint ecPoint = new ECPoint(xCoord, yCoord);

        ECParameterSpec ecParams = getEcParameterSpec(crv);
        if (ecParams == null) {
            throw new StatusListException("Unsupported EC curve: " + crv);
        }

        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParams);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(ecPublicKeySpec);
    }

    /**
     * Gets EC parameter specification for the given curve.
     */
    private ECParameterSpec getEcParameterSpec(String crv) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            if (crv.equals("P-256")) {
                params.init(new ECGenParameterSpec("secp256r1"));
            } else if (crv.equals("P-384")) {
                params.init(new ECGenParameterSpec("secp384r1"));
            } else if (crv.equals("P-521")) {
                params.init(new ECGenParameterSpec("secp521r1"));
            } else {
                return null;
            }
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            logger.warnf("Failed to get EC parameter spec for curve: %s", crv);
            return null;
        }
    }

    /**
     * Creates a revocation record for the specified credential.
     */
    private TokenStatusRecord createRevocationRecord(CredentialRevocationRequest request, String requestId) 
            throws StatusListException {
        
        logger.infof("Creating revocation record. RequestId: %s, CredentialId: %s", 
                     requestId, request.getCredentialId());
        
        try {
            RealmModel realm = session.getContext().getRealm();
            
            validateRevocationReason(request.getRevocationReason());
            
            String[] keyAndAlg = getRealmPublicKeyAndAlg(realm);
            String publicKey = keyAndAlg[0];
            String algorithm = keyAndAlg[1];
            
            TokenStatusRecord record = new TokenStatusRecord();
            record.setCredentialId(request.getCredentialId());
            record.setIssuer(realm.getName());
            record.setIssuerId(realm.getName());
            record.setPublicKey(publicKey);
            record.setAlg(algorithm);
            record.setStatus(TokenStatus.REVOKED);
            record.setCredentialType("oauth2");
            record.setRevokedAt(Instant.now());
            record.setStatusReason(request.getRevocationReason() != null ? 
                                 request.getRevocationReason() : "Credential revoked");
            
            logger.infof("Created revocation record. RequestId: %s, CredentialId: %s, Status: %s", 
                         requestId, record.getCredentialId(), record.getStatus());
            
            logger.infof("Revocation record details - Issuer: %s, Algorithm: %s, Reason: %s", 
                         record.getIssuer(), record.getAlg(), record.getStatusReason());
            
            return record;
            
        } catch (Exception e) {
            logger.errorf("Failed to create revocation record. RequestId: %s, Error: %s", 
                         requestId, e.getMessage());
            throw new StatusListException("Failed to create revocation record: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the realm's public key and algorithm for token verification.
     * Throws StatusListException if no valid key is available.
     */
    private String[] getRealmPublicKeyAndAlg(RealmModel realm) throws StatusListException {
        try {
            KeyManager keyManager = session.keys();
            KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, "RS256");
            
            if (activeKey == null) {
                throw new StatusListException("No active signing key found for realm: " + realm.getName());
            }
            
            if (activeKey.getPublicKey() == null) {
                throw new StatusListException("Active key has no public key for realm: " + realm.getName());
            }
            
            String publicKey = activeKey.getPublicKey().toString();
            String algorithm = activeKey.getAlgorithm() != null ? activeKey.getAlgorithm() : "RS256";
            
            logger.debugf("Retrieved public key and algorithm for realm %s: %s", realm.getName(), algorithm);
            return new String[]{publicKey, algorithm};
            
        } catch (StatusListException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error retrieving realm public key and algorithm", e);
            throw new StatusListException("Failed to retrieve realm public key: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the holder's signing key from the token's cnf.jwk field.
     * This is the key that the credential holder used to sign the VP token.
     */
    private PublicKey extractSigningKeyFromToken(SdJwtVP sdJwtVP) {
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
                
                PublicKey publicKey = extractPublicKeyFromJwksKey(jwkNode);
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
} 
