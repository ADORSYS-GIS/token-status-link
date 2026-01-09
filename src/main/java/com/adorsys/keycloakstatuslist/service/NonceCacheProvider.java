package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;

/**
 * Provider interface for nonce cache operations.
 * Simplified interface without extending Keycloak Provider.
 */
public interface NonceCacheProvider {
    
    /**
     * Issues a new nonce challenge for credential revocation.
     * 
     * @param credentialId the credential ID this nonce is bound to
     * @param audience the expected audience (revocation endpoint URL)
     * @return the generated nonce string
     */
    String issueNonce(String credentialId, String audience);
    
    /**
     * Consumes a nonce, validating and removing it from the cache.
     * 
     * @param nonce the nonce to consume
     * @return the RevocationChallenge if valid and not expired, null otherwise
     */
    RevocationChallenge consumeNonce(String nonce);
    
    /**
     * Gets the current cache size for monitoring purposes.
     * @return the number of active nonces in the cache
     */
    long getCacheSize();
    
    /**
     * Clears all nonces from the cache.
     */
    void clearCache();
}
