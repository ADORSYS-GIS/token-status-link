package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StatusTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testSerialization() throws Exception {
        StatusListClaim claim = new StatusListClaim(5L, "https://example.com/statuslist/5");
        Status status = new Status(claim);
        String json = objectMapper.writeValueAsString(status);
        assertTrue(json.contains("\"status_list\":{"));
        assertTrue(json.contains("\"idx\":5"));
        assertTrue(json.contains("\"uri\":\"https://example.com/statuslist/5\""));
    }

    @Test
    void testDeserialization() throws Exception {
        String json = "{\"status_list\":{\"idx\":7,\"uri\":\"https://foo.bar/list\"}}";
        Status status = objectMapper.readValue(json, Status.class);
        assertNotNull(status.getStatusList());
        assertEquals(7L, status.getStatusList().getIdx());
        assertEquals("https://foo.bar/list", status.getStatusList().getUri());
    }

    @Test
    void testSerializeAndDeserializeEquality() throws Exception {
        StatusListClaim claim = new StatusListClaim(42L, "https://baz.com/list");
        Status original = new Status(claim);
        String json = objectMapper.writeValueAsString(original);
        Status deserialized = objectMapper.readValue(json, Status.class);
        assertEquals(original, deserialized);
    }

    @Test
    void testDeserializationWithExtraFields() throws Exception {
        String json = "{\"status_list\":{\"idx\":9,\"uri\":\"https://x.y/z\",\"extra\":\"ignored\"},\"other\":123}";
        Status status = objectMapper.readValue(json, Status.class);
        assertEquals(9L, status.getStatusList().getIdx());
        assertEquals("https://x.y/z", status.getStatusList().getUri());
    }
}

