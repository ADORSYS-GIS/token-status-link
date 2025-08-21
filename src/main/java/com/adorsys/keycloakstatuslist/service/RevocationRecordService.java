package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeyManager;

import java.time.Instant;

/**
 * Service for creating and managing revocation records.
 * Handles the creation of TokenStatusRecord objects for revoked credentials.
 */
public class RevocationRecordService {
    
    private static final Logger logger = Logger.getLogger(RevocationRecordService.class);
    
    private final KeycloakSession session;
    
    public RevocationRecordService(KeycloakSession session) {
        this.session = session;
    }
    
    /**
     * Creates a revocation record for the specified credential.
     */
    public TokenStatusRecord createRevocationRecord(CredentialRevocationRequest request, String requestId) 
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
            record.setStatusReason(request.getRevocationReason() != null && !request.getRevocationReason().trim().isEmpty() ? 
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
     * Validates the revocation reason.
     */
    public void validateRevocationReason(String reason) throws StatusListException {
        if (reason != null && reason.length() > 255) {
            throw new StatusListException("Revocation reason exceeds maximum length of 255 characters");
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
} 
