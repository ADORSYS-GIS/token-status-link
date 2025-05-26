package com.adorsys.keycloakstatuslist;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;

import com.adorsys.keycloakstatuslist.client.StatusListClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;

@ExtendWith(MockitoExtension.class)
public class StatusListClientTest {

    private static final String SERVER_URL = "https://statuslist.example.com/";
    private static final String AUTH_TOKEN = "test-token";

    private StatusListClient client;

    @Mock
    private CloseableHttpClient httpClient;

    @Mock
    private CloseableHttpResponse httpResponse;

    @Mock
    private HttpEntity httpEntity;

    @BeforeEach
    void setUp() {
        client = new StatusListClient(SERVER_URL, AUTH_TOKEN);
    }

    @Test
    void testPublishTokenStatusLogoutPayload() throws IOException, URISyntaxException {
        // Setup mocks
        try (MockedStatic<org.apache.hc.client5.http.impl.classic.HttpClients> httpClientsMock =
                     mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {
            org.apache.hc.client5.http.impl.classic.HttpClientBuilder mockBuilder =
                    mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);
            httpClientsMock.when(HttpClients::custom)
                    .thenReturn(mockBuilder);

            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);

            // Only mock what's actually needed
            when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
            when(httpResponse.getCode()).thenReturn(201);

            // Execute
            boolean result = client.publishTokenStatus("token123", "LOGOUT");

            // Verify
            assertTrue(result);
            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
            verify(httpClient).execute(requestCaptor.capture());

            HttpPost capturedRequest = requestCaptor.getValue();
            StringEntity entity = (StringEntity) capturedRequest.getEntity();

            // Extract JSON payload from StringEntity
            String jsonPayload = new String(entity.getContent().readAllBytes());
            ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
            TokenStatusRecord sentRecord = mapper.readValue(jsonPayload, TokenStatusRecord.class);

            assertEquals("token123", sentRecord.getCredentialId());
            assertEquals(TokenStatus.REVOKED.getValue(), sentRecord.getStatus());
            assertNotNull(sentRecord.getRevokedAt());
            assertEquals("User logout or token revocation", sentRecord.getStatusReason());
        }
    }

    @Test
    void testPublishTokenStatusLogin() throws IOException, URISyntaxException {
        try (MockedStatic<org.apache.hc.client5.http.impl.classic.HttpClients> httpClientsMock =
                     mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {

            // 1. Create and configure the mock builder
            org.apache.hc.client5.http.impl.classic.HttpClientBuilder mockBuilder =
                    mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);

            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);

            // 2. Setup the static mock
            httpClientsMock.when(HttpClients::custom)
                    .thenReturn(mockBuilder);

            // 3. Only mock what's actually needed for this test
            when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
            when(httpResponse.getCode()).thenReturn(201);

            // Execute
            boolean result = client.publishTokenStatus("token123", "LOGIN");

            // Verify
            assertTrue(result);

            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
            verify(httpClient).execute(requestCaptor.capture());

            HttpPost capturedRequest = requestCaptor.getValue();
            assertEquals("https://statuslist.example.com/credentials", capturedRequest.getUri().toString());
        }
    }

    @Test
    void testPublishRecordServerError() throws IOException {
        try (MockedStatic<org.apache.hc.client5.http.impl.classic.HttpClients> httpClientsMock =
                     mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {

            // Create the mock builder
            org.apache.hc.client5.http.impl.classic.HttpClientBuilder mockBuilder =
                    mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);

            // Setup the static mock to return our mock builder
            httpClientsMock.when(HttpClients::custom)
                    .thenReturn(mockBuilder);

            // Configure the mock builder
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);

            // Setup HTTP response behavior
            when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
            when(httpResponse.getCode()).thenReturn(500);
            when(httpResponse.getEntity()).thenReturn(httpEntity);
            when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream("Server Error".getBytes()));

            // Create a valid token status record
            TokenStatusRecord record = new TokenStatusRecord();
            record.setCredentialId("token123");
            record.setIssuerId("test-issuer");
            record.setCredentialType("oauth2");
            record.setStatus(TokenStatus.VALID);
            record.setIssuedAt(Instant.now());
            record.setExpiresAt(Instant.now().plusSeconds(3600));

            // Execute
            boolean result = client.publishRecord(record);

            // Verify
            assertFalse(result);

            // Verify the HTTP client was called
            verify(httpClient).execute(any(HttpPost.class));
        }
    }

    @Test
    void testPublishRecordNetworkError() throws IOException {
        try (MockedStatic<org.apache.hc.client5.http.impl.classic.HttpClients> httpClientsMock =
                     mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {

            // Create the mock builder
            org.apache.hc.client5.http.impl.classic.HttpClientBuilder mockBuilder =
                    mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);

            // Setup the static mock
            httpClientsMock.when(HttpClients::custom)
                    .thenReturn(mockBuilder);

            // Configure the builder
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);

            // Configure the HTTP client behavior
            when(httpClient.execute(any(HttpPost.class))).thenThrow(new IOException("Network error"));

            // Create a valid token status record
            TokenStatusRecord record = new TokenStatusRecord();
            record.setCredentialId("token123");
            record.setIssuerId("test-issuer");
            record.setCredentialType("oauth2");
            record.setStatus(TokenStatus.VALID);
            record.setIssuedAt(Instant.now());
            record.setExpiresAt(Instant.now().plusSeconds(3600));

            // Execute
            boolean result = client.publishRecord(record);

            // Verify
            assertFalse(result);

            // Verify the HTTP client was called
            verify(httpClient).execute(any(HttpPost.class));
        }
    }

    @Test
    void testValidateStatusRecordMissingRequiredFields() {
        // Create a token status record with missing required fields
        TokenStatusRecord record = new TokenStatusRecord();

        // Test missing credentialId
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            client.publishRecord(record);
        });
        assertTrue(exception.getMessage().contains("Credential ID (sub) is required"));

        // Test missing issuerId
        record.setCredentialId("token123");
        exception = assertThrows(IllegalArgumentException.class, () -> {
            client.publishRecord(record);
        });
        assertTrue(exception.getMessage().contains("Issuer ID (iss) is required"));
    }

    @Test
    void testRevokedTokenValidation() throws IOException {
        try (MockedStatic<org.apache.hc.client5.http.impl.classic.HttpClients> httpClientsMock = mockStatic(org.apache.hc.client5.http.impl.classic.HttpClients.class)) {
            // Create and configure the mock builder
            org.apache.hc.client5.http.impl.classic.HttpClientBuilder mockBuilder = mock(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class);
            when(mockBuilder.setDefaultRequestConfig(any())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(httpClient);

            // Configure the static mock
            httpClientsMock.when(HttpClients::custom)
                    .thenReturn(mockBuilder);

            // Only mock what's actually needed
            when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);
            when(httpResponse.getCode()).thenReturn(201);

            // Create test record
            TokenStatusRecord record = new TokenStatusRecord();
            record.setCredentialId("token123");
            record.setIssuerId("test-issuer");
            record.setCredentialType("oauth2");
            record.setStatus(TokenStatus.REVOKED);

            // Execute
            boolean result = client.publishRecord(record);

            // Verify
            assertTrue(result);

            ArgumentCaptor<HttpPost> requestCaptor = ArgumentCaptor.forClass(HttpPost.class);
            verify(httpClient).execute(requestCaptor.capture());

            HttpPost capturedRequest = requestCaptor.getValue();
            assertNotNull(capturedRequest);
        }
    }
}