package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.vp.SdJwtVP;

import java.time.Instant;
import java.util.UUID;

/**
 * Main service for handling credential revocation requests.
 * Orchestrates the revocation process using specialized service classes.
 */
public class CredentialRevocationService {

    private static final Logger logger = Logger.getLogger(CredentialRevocationService.class);

    private final KeycloakSession session;
    private final SdJwtVPValidationService sdJwtVPValidationService;
    private final RevocationRecordService revocationRecordService;
    private final RequestValidationService requestValidationService;
    private StatusListService statusListService;

    public CredentialRevocationService(KeycloakSession session) {
        this.session = session;
        this.sdJwtVPValidationService = new SdJwtVPValidationService(session);
        this.revocationRecordService = new RevocationRecordService(session);
        this.requestValidationService = new RequestValidationService();
    }

    /**
     * Gets or creates the StatusListService instance.
     */
    private StatusListService getStatusListService() {
        if (statusListService == null) {
            RealmModel realm = session.getContext().getRealm();
            StatusListConfig config = new StatusListConfig(realm);
            CryptoIdentityService cryptoIdentityService = new CryptoIdentityService(session);
            this.statusListService = new StatusListService(
                    config.getServerUrl(),
                    cryptoIdentityService.getJwtToken(config),
                    CustomHttpClient.getHttpClient()
            );
        }
        return statusListService;
    }

    /**
     * Processes a credential revocation request.
     *
     * @param request      the revocation request containing credential ID and revocation reason
     * @param sdJwtVpToken the SD-JWT VP token from the Authorization header
     * @return response indicating success or failure of the revocation
     * @throws StatusListException if revocation processing fails
     */
    public CredentialRevocationResponse revokeCredential(CredentialRevocationRequest request, String sdJwtVpToken)
            throws StatusListException {

        String requestId = UUID.randomUUID().toString();

        requestValidationService.validateRevocationRequest(request);

        logger.infof("Processing credential revocation request. RequestId: %s, CredentialId: %s",
                requestId, request.getCredentialId());

        try {
            // Step 1: Parse the SD-JWT VP (without full verification yet)
            SdJwtVP sdJwtVP = sdJwtVPValidationService.parseSdJwtVP(sdJwtVpToken, requestId);
            
            // Step 2: SECURITY - Validate nonce to prevent replay attacks
            RevocationChallenge challenge = validateNonce(sdJwtVP, request.getCredentialId(), requestId);
            
            // Step 3: Verify the SD-JWT VP signature using the expected nonce from the challenge
            sdJwtVPValidationService.verifySdJwtVPSignature(sdJwtVP, requestId, request.getCredentialId(), challenge.nonce());
            
            // Step 4: Verify credential ownership
            sdJwtVPValidationService.verifyCredentialOwnership(sdJwtVP, request.getCredentialId(), requestId);
            
            // Step 5: Publish revocation record
            TokenStatusRecord revocationRecord = revocationRecordService.createRevocationRecord(request, requestId);
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
     * Validates the nonce from the Key Binding JWT to prevent replay attacks.
     * This is a critical security check that ensures each revocation request uses a fresh, one-time nonce.
     * 
     * @param sdJwtVP the SD-JWT VP token
     * @param credentialId the credential ID being revoked
     * @param requestId the request ID for logging
     * @return the validated RevocationChallenge containing the expected nonce
     * @throws StatusListException if nonce validation fails
     */
    private RevocationChallenge validateNonce(SdJwtVP sdJwtVP, String credentialId, String requestId) 
            throws StatusListException {
        
        // Extract nonce from Key Binding JWT
        String presentedNonce = sdJwtVPValidationService.extractNonceFromKeyBindingJWT(sdJwtVP);
        
        if (presentedNonce == null || presentedNonce.trim().isEmpty()) {
            logger.errorf("Missing nonce in Key Binding JWT. RequestId: %s, CredentialId: %s", 
                         requestId, credentialId);
            throw new StatusListException("Invalid or missing nonce in Key Binding JWT", 401);
        }
        
        // Get nonce service provider via RealmResourceProvider
        NonceCacheProvider nonceService = (NonceCacheProvider) session.getProvider(
            org.keycloak.services.resource.RealmResourceProvider.class, 
            "nonce-cache"
        );
        if (nonceService == null) {
            logger.errorf("NonceCacheProvider not available. RequestId: %s", requestId);
            throw new StatusListException("Nonce validation service not available", 500);
        }
        
        // Consume the nonce (one-time use)
        RevocationChallenge challenge = nonceService.consumeNonce(presentedNonce);
        
        if (challenge == null) {
            logger.errorf("Invalid, expired, or replayed nonce. RequestId: %s, Nonce: %s, CredentialId: %s", 
                         requestId, presentedNonce, credentialId);
            throw new StatusListException("Invalid, expired, or replayed nonce", 401);
        }
        
        // Optional: Verify nonce was issued for this specific credential
        if (challenge.credentialId() != null && !challenge.credentialId().equals(credentialId)) {
            logger.errorf("Nonce credential ID mismatch. RequestId: %s, Expected: %s, Got: %s", 
                         requestId, challenge.credentialId(), credentialId);
            throw new StatusListException("Nonce was issued for a different credential", 401);
        }
        
        logger.infof("Nonce validated successfully. RequestId: %s, Nonce: %s, CredentialId: %s", 
                    requestId, presentedNonce, credentialId);
        
        return challenge;
    }
}
