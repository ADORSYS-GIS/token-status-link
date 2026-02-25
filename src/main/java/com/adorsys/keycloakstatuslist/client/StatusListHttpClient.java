package com.adorsys.keycloakstatuslist.client;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.service.StatusListService.StatusListPayload;
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
     * Checks if a status list exists on the server.
     *
     * @param statusListId the status list identifier
     * @return true if the status list exists, false otherwise
     * @throws StatusListException if the operation fails
     */
    boolean checkStatusListExists(String statusListId) throws StatusListException;
    
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
    
    /**
     * Gets the URI for retrieving a status list.
     *
     * @param listId the status list identifier
     * @return the URI string for the status list
     */
    String getStatusListUri(String listId);
}


