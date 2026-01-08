package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.service.validation.RequestValidationService;

/**
 * Default implementation of RequestValidationService. Performs basic validation on request
 * parameters.
 */
public class RequestValidationServiceImpl implements RequestValidationService {

    /**
     * Validates a credential revocation request.
     *
     * @param request the revocation request to validate
     * @throws StatusListException if validation fails
     */
    @Override
    public void validateRevocationRequest(CredentialRevocationRequest request)
            throws StatusListException {
        if (request == null) {
            throw new StatusListException("Revocation request cannot be null");
        }

        if (request.getCredentialId() == null || request.getCredentialId().trim().isEmpty()) {
            throw new StatusListException("Credential ID is required");
        }
    }
}
