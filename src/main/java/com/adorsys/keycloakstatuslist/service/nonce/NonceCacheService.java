package com.adorsys.keycloakstatuslist.service.nonce;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import java.util.HashMap;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Service for managing nonce challenges in credential revocation.
 * Uses Keycloak's {@link SingleUseObjectProvider} (Infinispan-backed) so challenges
 * are shared across cluster nodes and consumed atomically (one-time use).
 * Implements RealmResourceProvider so Keycloak can discover it via standard SPI.
 */
public class NonceCacheService implements NonceCacheProvider, RealmResourceProvider {
    private static final Logger logger = Logger.getLogger(NonceCacheService.class);
    static final int NONCE_EXPIRATION_SECONDS = 600; // 10 minutes
    static final String KEY_PREFIX = "status-list-revocation:";
    static final String NOTE_AUD = "aud";
    static final String NOTE_EXP = "exp";
    static final String NOTE_EXPIRES_IN = "expires_in";

    private final KeycloakSession session;

    public NonceCacheService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Issues a new nonce challenge for credential revocation.
     *
     * @param audience the expected audience (revocation endpoint URL)
     * @return the generated challenge including nonce
     */
    @Override
    public RevocationChallenge issueNonce(String audience) {
        String nonce = SecretGenerator.getInstance().generateSecureID();
        RevocationChallenge challenge = new RevocationChallenge(nonce, audience, NONCE_EXPIRATION_SECONDS);

        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_AUD, audience);
        notes.put(NOTE_EXP, Long.toString(challenge.getExpiresAt()));
        notes.put(NOTE_EXPIRES_IN, Integer.toString(NONCE_EXPIRATION_SECONDS));

        singleUseObjects().put(cacheKey(nonce), NONCE_EXPIRATION_SECONDS, notes);

        logger.debugf("Issued nonce challenge: %s", challenge);
        return challenge;
    }

    /**
     * Consumes a nonce, validating and removing it from the shared store.
     * This ensures one-time use — subsequent calls with the same nonce will fail,
     * including across cluster nodes.
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

        Map<String, String> notes = singleUseObjects().remove(cacheKey(nonce));
        if (notes == null) {
            logger.warnf("Nonce not found in cache (may be already consumed or expired): %s", nonce);
            return null;
        }

        String audience = notes.get(NOTE_AUD);
        String expRaw = notes.get(NOTE_EXP);
        String expiresInRaw = notes.get(NOTE_EXPIRES_IN);
        if (audience == null || expRaw == null) {
            logger.warnf("Nonce notes incomplete for nonce: %s", nonce);
            return null;
        }

        long expiresAt;
        int expiresIn;
        try {
            expiresAt = Long.parseLong(expRaw);
            expiresIn = expiresInRaw != null ? Integer.parseInt(expiresInRaw) : NONCE_EXPIRATION_SECONDS;
        } catch (NumberFormatException e) {
            logger.warnf("Invalid expiration notes for nonce: %s", nonce);
            return null;
        }

        RevocationChallenge challenge = new RevocationChallenge();
        challenge.setNonce(nonce);
        challenge.setAudience(audience);
        challenge.setExpiresAt(expiresAt);
        challenge.setExpiresIn(expiresIn);

        if (challenge.isExpired()) {
            logger.warnf("Nonce has expired: %s, expiresAt=%s", nonce, challenge.getExpiresAt());
            return null;
        }

        logger.debugf("Successfully consumed nonce: %s", nonce);
        return challenge;
    }

    static String cacheKey(String nonce) {
        return KEY_PREFIX + nonce;
    }

    private SingleUseObjectProvider singleUseObjects() {
        return session.getProvider(SingleUseObjectProvider.class);
    }

    // RealmResourceProvider implementation
    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // Session-scoped; nothing to clean up. SingleUseObjectProvider owns the store.
    }
}
