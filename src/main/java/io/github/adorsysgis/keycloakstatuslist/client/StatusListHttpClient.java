package io.github.adorsysgis.keycloakstatuslist.client;

import io.github.adorsysgis.keycloakstatuslist.exception.StatusListException;
import io.github.adorsysgis.keycloakstatuslist.service.StatusListService.StatusListPayload;
import org.keycloak.jose.jwk.JWK;

/**
 * Interface for HTTP client operations to the status list server.
 */
public interface StatusListHttpClient {

    /**
     * Registers an issuer with the server.
     *
     * @param issuerId the issuer identifier
     * @param publicKey the issuer's public key
     * @throws StatusListException if the operation fails
     */
    void registerIssuer(String issuerId, JWK publicKey) throws StatusListException;

    /**
     * Publishes a new status list to the server.
     *
     * @param payload the status list payload
     * @param requestId correlation ID for tracking
     * @throws StatusListException if the operation fails
     */
    void publishStatusList(StatusListPayload payload, String requestId) throws StatusListException;

    /**
     * Updates an existing status list on the server.
     *
     * @param payload the status list payload
     * @param requestId correlation ID for tracking
     * @throws StatusListException if the operation fails
     */
    void updateStatusList(StatusListPayload payload, String requestId) throws StatusListException;

    /**
     * Checks the health status of the status list server.
     *
     * @return true if the server is healthy, false otherwise
     */
    boolean checkServerHealth();
}
