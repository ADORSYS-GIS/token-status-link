package com.adorsys.keycloakstatuslist.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RevocationChallengeTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testSerialization() throws Exception {
        RevocationChallenge challenge = new RevocationChallenge("nonce123", "audience456", 60);

        String json = objectMapper.writeValueAsString(challenge);

        assertTrue(json.contains("\"nonce\":\"nonce123\""));
        assertTrue(json.contains("\"aud\":\"audience456\""));
        assertTrue(json.contains("\"exp\":"));
    }

    @Test
    void testDeserialization() throws Exception {
        long exp = Instant.now().plusSeconds(120).getEpochSecond();
        String json = String.format("{\"nonce\":\"n1\",\"aud\":\"a2\",\"exp\":%d}", exp);

        RevocationChallenge challenge = objectMapper.readValue(json, RevocationChallenge.class);

        assertEquals("n1", challenge.getNonce());
        assertEquals("a2", challenge.getAudience());
        assertEquals(exp, challenge.getExpiresAt());
    }

    @Test
    void testIsExpired() {
        long now = Instant.now().getEpochSecond();

        RevocationChallenge expired = new RevocationChallenge("n", "a", -10); // already expired
        expired.setExpiresAt(now - 1);
        assertTrue(expired.isExpired());

        RevocationChallenge notExpired = new RevocationChallenge("n", "a", 1000);
        notExpired.setExpiresAt(now + 1000);
        assertFalse(notExpired.isExpired());
    }
}
