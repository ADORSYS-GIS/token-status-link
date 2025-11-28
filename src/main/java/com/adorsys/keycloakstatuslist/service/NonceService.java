package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.model.NonceChallenge;
import org.keycloak.models.KeycloakSession;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class NonceService {

    private static final int NONCE_LENGTH = 32; // 256 bits
    private static final long NONCE_EXPIRATION_SECONDS = 300; // 5 minutes
    private static final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, NonceChallenge> nonceStore = new ConcurrentHashMap<>();

    private final KeycloakSession session;

    public NonceService(KeycloakSession session) {
        this.session = session;
    }

    public NonceChallenge generateAndStoreNonce(String requestId, String audience) {
        String nonce = generateNonce();
        long expiresAt = System.currentTimeMillis() / 1000 + NONCE_EXPIRATION_SECONDS;
        NonceChallenge challenge = new NonceChallenge(nonce, audience, expiresAt);
        nonceStore.put(requestId, challenge);
        return challenge;
    }

    public NonceChallenge getAndRemoveNonceChallenge(String requestId) {
        return nonceStore.remove(requestId);
    }

    private String generateNonce() {
        byte[] nonceBytes = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonceBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    }

    public boolean validateNonce(String requestId, String vpNonce, String expectedAudience) {
        NonceChallenge storedChallenge = getAndRemoveNonceChallenge(requestId); // Remove after first use to prevent replay

        if (storedChallenge == null) {
            return false; // Nonce not found or already used
        }

        if (!storedChallenge.getNonce().equals(vpNonce)) {
            return false; // Nonce mismatch
        }

        if (!storedChallenge.getAud().equals(expectedAudience)) {
            return false; // Audience mismatch
        }

        if (System.currentTimeMillis() / 1000 > storedChallenge.getExpires_in()) {
            return false; // Nonce expired
        }

        return true;
    }
}