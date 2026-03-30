package com.adorsys.keycloakstatuslist.service.nonce;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertFalse(challenge.getNonce().trim().isEmpty());
        assertEquals("https://example.com/revoke", challenge.getAudience());
        assertEquals(600, challenge.getExpiresIn());
        assertTrue(challenge.getExpiresAt() > Instant.now().getEpochSecond());
        assertEquals(1, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldReturnNullWhenNonceDoesNotExistInCache() {
        RevocationChallenge consumed = nonceCacheService.consumeNonce("unknown-nonce");
        assertNull(consumed);
        assertEquals(0, nonceCacheService.getCacheSize());
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
    void shouldConsumeOnlyRequestedNonceWhenMultipleAreInCache() {
        RevocationChallenge first = nonceCacheService.issueNonce("https://example.com/revoke/first");
        RevocationChallenge second = nonceCacheService.issueNonce("https://example.com/revoke/second");

        RevocationChallenge consumedFirst = nonceCacheService.consumeNonce(first.getNonce());
        RevocationChallenge consumedSecond = nonceCacheService.consumeNonce(second.getNonce());

        assertNotNull(consumedFirst);
        assertEquals(first.getNonce(), consumedFirst.getNonce());
        assertNotNull(consumedSecond);
        assertEquals(second.getNonce(), consumedSecond.getNonce());
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
        challenge.setExpiresAt(Instant.now().minusSeconds(5).getEpochSecond());
        assertTrue(challenge.isExpired(), "Precondition failed: challenge must be expired for this scenario");
        assertEquals(1, nonceCacheService.getCacheSize());

        RevocationChallenge consumed = nonceCacheService.consumeNonce(challenge.getNonce());
        RevocationChallenge consumedAgain = nonceCacheService.consumeNonce(challenge.getNonce());

        assertNull(consumed);
        assertNull(consumedAgain);
        assertEquals(0, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldConsumeNonceWhenExpiresAtIsCurrentOrFuture() {
        RevocationChallenge challenge = nonceCacheService.issueNonce("https://example.com/revoke");
        challenge.setExpiresAt(Instant.now().plusSeconds(1).getEpochSecond());

        RevocationChallenge consumed = nonceCacheService.consumeNonce(challenge.getNonce());

        assertNotNull(consumed);
        assertEquals(challenge.getNonce(), consumed.getNonce());
        assertEquals(0, nonceCacheService.getCacheSize());
    }

    @Test
    void shouldClearCache() {
        nonceCacheService.issueNonce("https://example.com/revoke");
        nonceCacheService.issueNonce("https://example.com/revoke");
        assertEquals(2, nonceCacheService.getCacheSize());

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
