package com.adorsys.keycloakstatuslist.service.validation;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;

/**
 * Interface for request validation services. Allows alternative validation strategies to be
 * implemented.
 */
public interface RequestValidationService {

    /**
     * Validates a credential revocation request.
     *
     * @param request the revocation request to validate
     * @throws StatusListException if validation fails
     */
    void validateRevocationRequest(CredentialRevocationRequest request) throws StatusListException;
}

