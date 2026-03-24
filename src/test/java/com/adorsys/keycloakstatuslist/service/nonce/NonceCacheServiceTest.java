package com.adorsys.keycloakstatuslist.service.nonce;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NonceCacheServiceTest {

    private NonceCacheService nonceCacheService;

    @BeforeEach
    void setUp() {
        nonceCacheService = new NonceCacheService();
    }

    @Test
    void shouldIssueNonceAndStoreChallenge() {
        RevocationChallenge challenge = nonceCacheService.issueNonce("https://example.com/revoke");

        assertNotNull(challenge.getNonce());
        assertEquals("https://example.com/revoke", challenge.getAudience());
        assertEquals(600, challenge.getExpiresIn());
        assertEquals(1, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldConsumeNonceOnlyOnce() {
        RevocationChallenge issued = nonceCacheService.issueNonce("https://example.com/revoke");

        RevocationChallenge firstConsume = nonceCacheService.consumeNonce(issued.getNonce());
        RevocationChallenge secondConsume = nonceCacheService.consumeNonce(issued.getNonce());

        assertNotNull(firstConsume);
        assertEquals(issued.getNonce(), firstConsume.getNonce());
        assertNull(secondConsume);
        assertEquals(0, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldReturnNullForNullOrBlankNonce() {
        assertNull(nonceCacheService.consumeNonce(null));
        assertNull(nonceCacheService.consumeNonce(""));
        assertNull(nonceCacheService.consumeNonce("   "));
    }

    @Test
    void shouldRejectExpiredNonceAndRemoveItFromCache() {
        RevocationChallenge challenge = nonceCacheService.issueNonce("https://example.com/revoke");
        challenge.setExpiresAt(Instant.now().minusSeconds(1).getEpochSecond());

        RevocationChallenge consumed = nonceCacheService.consumeNonce(challenge.getNonce());

        assertNull(consumed);
        assertEquals(0, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldClearCache() {
        nonceCacheService.issueNonce("https://example.com/revoke");
        nonceCacheService.issueNonce("https://example.com/revoke");

        nonceCacheService.clearCache();

        assertEquals(0, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldExposeItselfAsRealmResource() {
        Object resource = nonceCacheService.getResource();
        assertSame(nonceCacheService, resource);
    }

    @Test
    void closeShouldCleanupWithoutThrowing() {
        nonceCacheService.issueNonce("https://example.com/revoke");
        nonceCacheService.close();
        // No assertion needed beyond "no exception thrown".
    }
}
