package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;

/**
 * Service for validating credential revocation requests.
 * Performs basic validation on request parameters.
 */
public class RequestValidationService {
    
    /**
     * Validates the revocation request parameters.
     * 
     * @param request the revocation request to validate
     * @throws StatusListException if validation fails
     */
    public void validateRevocationRequest(CredentialRevocationRequest request) throws StatusListException {
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
} 
