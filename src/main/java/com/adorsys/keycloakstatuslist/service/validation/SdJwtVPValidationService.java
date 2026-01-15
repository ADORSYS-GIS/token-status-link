package com.adorsys.keycloakstatuslist.service.validation;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Interface for SD-JWT VP token validation services. Allows alternative implementations for
 * different validation strategies.
 */
public interface SdJwtVPValidationService {

    /**
     * Parses and validates the SD-JWT VP token. This validates the token structure, parses it for
     * credential extraction, and performs cryptographic signature verification.
     *
     * @param sdJwtVpString the SD-JWT VP token string
     * @param requestId     the request ID for logging and tracing
     * @return the parsed and validated SdJwtVP object
     * @throws StatusListException if validation fails
     */
    SdJwtVP parseAndValidateSdJwtVP(String sdJwtVpString, String requestId) throws StatusListException;

    /**
     * Verifies that the SD-JWT VP token proves ownership of the specified credential. This includes
     * credential ID matching, holder signature verification, and key binding validation.
     *
     * @param sdJwtVP     the parsed SD-JWT VP token
     * @param credentialId the credential ID to verify ownership for
     * @param requestId   the request ID for logging
     * @throws StatusListException if ownership verification fails
     */
    void verifyCredentialOwnership(SdJwtVP sdJwtVP, String credentialId, String requestId)
            throws StatusListException;
}

