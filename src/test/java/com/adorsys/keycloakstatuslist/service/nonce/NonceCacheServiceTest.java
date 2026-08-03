package com.adorsys.keycloakstatuslist.service.nonce;

import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.KEY_PREFIX;
import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.NONCE_EXPIRATION_SECONDS;
import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.NOTE_AUD;
import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.NOTE_EXP;
import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.NOTE_EXPIRES_IN;
import static com.adorsys.keycloakstatuslist.service.nonce.NonceCacheService.cacheKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.ArgumentCaptor;

class NonceCacheServiceTest {

    private KeycloakSession session;
    private SingleUseObjectProvider singleUseObjects;
    private NonceCacheService nonceCacheService;

    /** Simple in-memory store to simulate put/remove semantics for integration-style unit tests. */
    private final Map<String, Map<String, String>> store = new ConcurrentHashMap<>();

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        singleUseObjects = mock(SingleUseObjectProvider.class);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseObjects);

        // Default: put stores notes; remove returns and deletes them (one-time use).
        org.mockito.Mockito.doAnswer(invocation -> {
                    String key = invocation.getArgument(0);
                    Map<String, String> notes = invocation.getArgument(2);
                    store.put(key, new HashMap<>(notes));
                    return null;
                })
                .when(singleUseObjects)
                .put(anyString(), eq((long) NONCE_EXPIRATION_SECONDS), anyMap());

        when(singleUseObjects.remove(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return store.remove(key);
        });

        nonceCacheService = new NonceCacheService(session);
    }

    @Test
    void shouldIssueNonceAndStoreChallenge() {
        RevocationChallenge challenge = nonceCacheService.issueNonce("https://example.com/revoke");

        assertNotNull(challenge.getNonce());
        assertFalse(challenge.getNonce().trim().isEmpty());
        assertEquals("https://example.com/revoke", challenge.getAudience());
        assertEquals(600, challenge.getExpiresIn());
        assertTrue(challenge.getExpiresAt() > Instant.now().getEpochSecond());

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> notesCaptor = ArgumentCaptor.forClass(Map.class);

        verify(singleUseObjects)
                .put(keyCaptor.capture(), eq((long) NONCE_EXPIRATION_SECONDS), notesCaptor.capture());

        assertEquals(KEY_PREFIX + challenge.getNonce(), keyCaptor.getValue());
        assertEquals("https://example.com/revoke", notesCaptor.getValue().get(NOTE_AUD));
        assertEquals(Long.toString(challenge.getExpiresAt()), notesCaptor.getValue().get(NOTE_EXP));
        assertEquals(Integer.toString(NONCE_EXPIRATION_SECONDS), notesCaptor.getValue().get(NOTE_EXPIRES_IN));
    }

    @Test
    void shouldReturnNullWhenNonceDoesNotExistInCache() {
        RevocationChallenge consumed = nonceCacheService.consumeNonce("unknown-nonce");
        assertNull(consumed);
        verify(singleUseObjects).remove(cacheKey("unknown-nonce"));
    }

    @Test
    void shouldConsumeNonceOnlyOnce() {
        RevocationChallenge issued = nonceCacheService.issueNonce("https://example.com/revoke");

        RevocationChallenge firstConsume = nonceCacheService.consumeNonce(issued.getNonce());
        RevocationChallenge secondConsume = nonceCacheService.consumeNonce(issued.getNonce());

        assertNotNull(firstConsume);
        assertEquals(issued.getNonce(), firstConsume.getNonce());
        assertEquals(issued.getAudience(), firstConsume.getAudience());
        assertNull(secondConsume);
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
    }

    @Test
    void shouldReturnNullForNullOrBlankNonce() {
        assertNull(nonceCacheService.consumeNonce(null));
        assertNull(nonceCacheService.consumeNonce(""));
        assertNull(nonceCacheService.consumeNonce("   "));
        verify(singleUseObjects, never()).remove(anyString());
    }

    @Test
    void shouldRejectExpiredNonce() {
        String nonce = "expired-nonce";
        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_AUD, "https://example.com/revoke");
        notes.put(NOTE_EXP, Long.toString(Instant.now().minusSeconds(5).getEpochSecond()));
        notes.put(NOTE_EXPIRES_IN, "600");
        when(singleUseObjects.remove(cacheKey(nonce))).thenReturn(notes);

        RevocationChallenge consumed = nonceCacheService.consumeNonce(nonce);
        RevocationChallenge consumedAgain = nonceCacheService.consumeNonce(nonce);

        assertNull(consumed);
        assertNull(consumedAgain);
    }

    @Test
    void shouldConsumeNonceWhenExpiresAtIsCurrentOrFuture() {
        String nonce = "valid-nonce";
        long expiresAt = Instant.now().plusSeconds(60).getEpochSecond();
        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_AUD, "https://example.com/revoke");
        notes.put(NOTE_EXP, Long.toString(expiresAt));
        notes.put(NOTE_EXPIRES_IN, "600");
        when(singleUseObjects.remove(cacheKey(nonce))).thenReturn(notes);

        RevocationChallenge consumed = nonceCacheService.consumeNonce(nonce);

        assertNotNull(consumed);
        assertEquals(nonce, consumed.getNonce());
        assertEquals("https://example.com/revoke", consumed.getAudience());
        assertEquals(expiresAt, consumed.getExpiresAt());
    }

    @Test
    void shouldReturnNullWhenNotesAreIncomplete() {
        String nonce = "incomplete-nonce";
        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_AUD, "https://example.com/revoke");
        // missing exp
        when(singleUseObjects.remove(cacheKey(nonce))).thenReturn(notes);

        assertNull(nonceCacheService.consumeNonce(nonce));
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
