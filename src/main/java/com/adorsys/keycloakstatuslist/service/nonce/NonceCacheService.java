package com.adorsys.keycloakstatuslist.service.nonce;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.services.resource.RealmResourceProvider;

import java.time.Duration;

/**
 * Service for managing nonce challenges in credential revocation.
 * Uses an in-memory cache with automatic expiration to prevent replay attacks.
 * Implements RealmResourceProvider so Keycloak can discover it via standard SPI.
 */
public class NonceCacheService implements NonceCacheProvider, RealmResourceProvider {
    
    private static final Logger logger = Logger.getLogger(NonceCacheService.class);
    private static final int NONCE_EXPIRATION_SECONDS = 600; // 10 minutes
    private static final int MAX_CACHE_SIZE = 50_000;
    
    // Thread-safe cache with automatic expiration
    private final Cache<String, RevocationChallenge> cache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(NONCE_EXPIRATION_SECONDS))
            .maximumSize(MAX_CACHE_SIZE)
            .build();
    
    /**
     * Issues a new nonce challenge for credential revocation.
     *
     * @param audience the expected audience (revocation endpoint URL)
     * @return the generated nonce string
     */
    @Override
    public RevocationChallenge issueNonce(String audience) {
        String nonce = SecretGenerator.getInstance().generateSecureID();

        RevocationChallenge challenge = new RevocationChallenge(nonce, audience, NONCE_EXPIRATION_SECONDS);
        cache.put(nonce, challenge);

        logger.debugf("Issued nonce challenge: nonce=%s, audience=%s, expiresIn=%s",
                nonce, audience, challenge.getExpiresIn());

        return challenge;
    }
    
    /**
     * Consumes a nonce, validating and removing it from the cache.
     * This ensures one-time use - subsequent calls with the same nonce will fail.
     * 
     * @param nonce the nonce to consume
     * @return the RevocationChallenge if valid and not expired, null otherwise
     */
    @Override
    public RevocationChallenge consumeNonce(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            logger.warn("Attempted to consume null or empty nonce");
            return null;
        }
        
        RevocationChallenge challenge = cache.getIfPresent(nonce);
        
        if (challenge == null) {
            logger.warnf("Nonce not found in cache (may be already consumed or expired): %s", nonce);
            return null;
        }
        
        if (challenge.isExpired()) {
            logger.warnf("Nonce has expired: %s, expiresIn=%s", nonce, challenge.getExpiresIn());
            cache.invalidate(nonce); // Clean up expired nonce
            return null;
        }
        
        // One-time use: remove from cache immediately
        cache.invalidate(nonce);
        logger.debugf("Successfully consumed nonce: %s", nonce);
        
        return challenge;
    }
    
    /**
     * Gets the current cache size for monitoring purposes.
     * @return the number of active nonces in the cache
     */
    @Override
    public long getCacheSize() {
        return cache.estimatedSize();
    }
    
    /**
     * Clears all nonces from the cache.
     * Used primarily for testing and maintenance.
     */
    @Override
    public void clearCache() {
        cache.invalidateAll();
        logger.info("Nonce cache cleared");
    }
    
    // RealmResourceProvider implementation
    @Override
    public Object getResource() {
        return this;
    }
    
    @Override
    public void close() {
        cache.cleanUp();
        logger.debug("NonceCacheService closed and cache cleaned up");
    }
}
