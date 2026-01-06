package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.client.ApacheHttpStatusListClient;
import com.adorsys.keycloakstatuslist.client.StatusListHttpClient;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.jose.jwk.JWK;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class StatusListServiceTest {

    private static final String SERVER_URL = "https://status-list-server.adorsys.com";
    private static final String ISSUER_ID = "test-issuer";
    private static final String ALGORITHM = "RS256";

    @Mock
    private CloseableHttpClient httpClient;
    
    @Mock
    private JWK mockJwk;

    private StatusListService statusListService;

    @BeforeEach
    void setUp() {
        // Create HTTP client with no circuit breaker for testing
        StatusListHttpClient httpClientImpl = new ApacheHttpStatusListClient(
                SERVER_URL, null, httpClient, null);
        statusListService = new StatusListService(httpClientImpl);
    }

    private void setupResponse(int statusCode) throws IOException {
        setupResponse(statusCode, "{}");
    }
    
    private void setupResponse(int statusCode, String responseBody) throws IOException {
        doAnswer(invocation -> {
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);

            ClassicHttpResponse response = new BasicClassicHttpResponse(statusCode);
            response.setEntity(new StringEntity(responseBody));

            return handler.handleResponse(response);
        }).when(httpClient).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
    }

    private void setupSuccessfulResponse() throws IOException {
        setupResponse(200);
    }

    private void setupResponseWithStatus(int statusCode) throws IOException {
        setupResponse(statusCode);
    }

    private void verifyHttpClientCall(int expectedCalls) throws IOException {
        verify(httpClient, times(expectedCalls)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void successScenarios() throws IOException {
        // Test register issuer success
        setupSuccessfulResponse();
        // Updated to pass JWK object
        assertDoesNotThrow(() -> statusListService.registerIssuer(ISSUER_ID, mockJwk));
        verifyHttpClientCall(1);

        // Test publish record success
        assertDoesNotThrow(() -> {
            reset(httpClient);
            final TokenStatusRecord record = createTestRecord();
            setupSuccessfulResponse();
            statusListService.publishRecord(record);
            verifyHttpClientCall(1);
        });

        // Test publish record with auth token
        final TokenStatusRecord record = createTestRecord();
        reset(httpClient);
        StatusListHttpClient httpClientWithAuth = new ApacheHttpStatusListClient(
                SERVER_URL, "test-token", httpClient, null);
        statusListService = new StatusListService(httpClientWithAuth);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);
    }

    @Test
    void responseBodyScenarios() throws IOException {
        final TokenStatusRecord record = createTestRecord();

        // Test empty response body
        setupResponse(200, "");
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test non-empty response body
        reset(httpClient);
        setupResponse(200, "{\"status\":\"success\"}");
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test malformed JSON response
        reset(httpClient);
        setupResponse(200, "{invalid json}");
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);
    }

    @Test
    void registerIssuer_AlreadyRegistered() throws IOException {
        // Arrange
        assertDoesNotThrow(() -> {
            setupResponseWithStatus(409);

            // Act & Assert
            statusListService.registerIssuer(ISSUER_ID, mockJwk);
            verifyHttpClientCall(1);
        });
    }

    @Test
    void registerIssuer_ServerError() throws IOException {
        // Arrange
        setupResponseWithStatus(500);

        // Act & Assert
        StatusListServerException exception = assertThrows(StatusListServerException.class,
                () -> statusListService.registerIssuer(ISSUER_ID, mockJwk));
        assertEquals(500, exception.getStatusCode());
        assertDoesNotThrow(() -> verifyHttpClientCall(1));
    }

    @Test
    void publishRecord_ValidationScenarios() {
        // Test missing credential ID
        final TokenStatusRecord record1 = createTestRecord();
        record1.setCredentialId(null);
        StatusListException exception = assertThrows(StatusListException.class,
                () -> statusListService.publishRecord(record1));
        assertTrue(exception.getMessage().contains("Credential ID (sub) is required"));

        // Test missing issuer ID
        final TokenStatusRecord record2 = createTestRecord();
        record2.setIssuerId(null);
        exception = assertThrows(StatusListException.class,
                () -> statusListService.publishRecord(record2));
        assertTrue(exception.getMessage().contains("Issuer ID (iss) is required"));

        // Test missing public key
        final TokenStatusRecord record3 = createTestRecord();
        record3.setPublicKey(null);
        exception = assertThrows(StatusListException.class,
                () -> statusListService.publishRecord(record3));
        assertTrue(exception.getMessage().contains("Public key is required"));

    }

    @Test
    void publishRecord_DefaultValues() throws IOException {
        // Test default status
        assertDoesNotThrow(() -> {
            final TokenStatusRecord record1 = createTestRecord();
            record1.setStatus(TokenStatus.REVOKED);
            setupSuccessfulResponse();
            statusListService.publishRecord(record1);
            assertEquals(TokenStatus.REVOKED.getValue(), record1.getStatus());
            verifyHttpClientCall(1);
        });

        // Test default credential type
        assertDoesNotThrow(() -> {
            reset(httpClient);
            final TokenStatusRecord record2 = createTestRecord();
            record2.setCredentialType(null);
            setupSuccessfulResponse();
            statusListService.publishRecord(record2);
            assertEquals("oauth2", record2.getCredentialType());
            verifyHttpClientCall(1);
        });
    }

    @Test
    void publishRecord_StatusCodeHandling() throws IOException {
        TokenStatusRecord record = createTestRecord();

        // Test 200 OK
        assertDoesNotThrow(() -> {
            setupResponseWithStatus(200);
            statusListService.publishRecord(record);
            verifyHttpClientCall(1);
        });

        // Test 201 Created
        assertDoesNotThrow(() -> {
            reset(httpClient);
            setupResponseWithStatus(201);
            statusListService.publishRecord(record);
            verifyHttpClientCall(1);
        });

        // Test 204 No Content
        assertDoesNotThrow(() -> {
            reset(httpClient);
            setupResponseWithStatus(204);
            statusListService.publishRecord(record);
            verifyHttpClientCall(1);
        });

        // Test 409 Conflict (already registered)
        assertDoesNotThrow(() -> {
            reset(httpClient);
            setupResponseWithStatus(409);
            statusListService.publishRecord(record);
            verifyHttpClientCall(1);
        });

        // Test 400 Bad Request
        assertDoesNotThrow(() -> {
            reset(httpClient);
            setupResponseWithStatus(400);
            StatusListServerException exception = assertThrows(StatusListServerException.class,
                    () -> statusListService.publishRecord(record));
            assertEquals(400, exception.getStatusCode());
            verifyHttpClientCall(1);
        });
    }

    @Test
    void publishRecord_RecordFieldHandling() throws IOException {
        // Test issuer field is set from issuerId
        assertDoesNotThrow(() -> {
            final TokenStatusRecord record1 = createTestRecord();
            record1.setIssuer(null);
            record1.setIssuerId(ISSUER_ID);
            setupSuccessfulResponse();
            statusListService.publishRecord(record1);
            assertEquals(ISSUER_ID, record1.getIssuer());
            verifyHttpClientCall(1);
        });

        // Test index field is set to null when 0
        assertDoesNotThrow(() -> {
            reset(httpClient);
            final TokenStatusRecord record2 = createTestRecord();
            record2.setIndex(0L);
            setupSuccessfulResponse();
            statusListService.publishRecord(record2);
            assertNull(record2.getIndex());
            verifyHttpClientCall(1);
        });

        // Test status field default value
        assertDoesNotThrow(() -> {
            reset(httpClient);
            final TokenStatusRecord record3 = createTestRecord();
            record3.setStatus(TokenStatus.REVOKED);
            setupSuccessfulResponse();
            statusListService.publishRecord(record3);
            assertEquals(TokenStatus.REVOKED.getValue(), record3.getStatus());
            verifyHttpClientCall(1);
        });
    }

    private TokenStatusRecord createTestRecord() {
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId(UUID.randomUUID().toString());
        record.setIssuer(ISSUER_ID);
        record.setIssuerId(ISSUER_ID);
        record.setPublicKey(mockJwk); // Set mock JWK object
        record.setStatus(TokenStatus.VALID);
        record.setIssuedAt(Instant.now());
        record.setExpiresAt(Instant.now().plusSeconds(3600));
        return record;
    }

    @Test
    void publishOrUpdate_shouldPublish_whenListDoesNotExist() throws IOException {
        doAnswer(invocation -> {
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
            ClassicHttpResponse response = new BasicClassicHttpResponse(404);
            return handler.handleResponse(response);
        }).when(httpClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        doAnswer(invocation -> {
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
            ClassicHttpResponse response = new BasicClassicHttpResponse(201);
            return handler.handleResponse(response);
        }).when(httpClient).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));

        StatusListService.StatusListPayload payload = createTestPayload();

        assertDoesNotThrow(() -> statusListService.publishOrUpdate(payload));

        verify(httpClient, times(1)).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));
        verify(httpClient, times(1)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
        verify(httpClient, never()).execute(any(HttpPatch.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void publishOrUpdate_shouldUpdate_whenListExists() throws IOException {
        doAnswer(invocation -> {
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
            ClassicHttpResponse response = new BasicClassicHttpResponse(200);
            return handler.handleResponse(response);
        }).when(httpClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        doAnswer(invocation -> {
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
            ClassicHttpResponse response = new BasicClassicHttpResponse(200);
            return handler.handleResponse(response);
        }).when(httpClient).execute(any(HttpPatch.class), any(HttpClientResponseHandler.class));

        StatusListService.StatusListPayload payload = createTestPayload();

        assertDoesNotThrow(() -> statusListService.publishOrUpdate(payload));

        verify(httpClient, times(1)).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));
        verify(httpClient, never()).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
        verify(httpClient, times(1)).execute(any(HttpPatch.class), any(HttpClientResponseHandler.class));
    }

    @Test
    void publishOrUpdate_shouldThrowException_whenCheckFails() throws IOException {
        doThrow(new IOException("Server connection failed"))
                .when(httpClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        StatusListService.StatusListPayload payload = createTestPayload();

        StatusListException exception = assertThrows(StatusListException.class,
                () -> statusListService.publishOrUpdate(payload));

        assertTrue(exception.getMessage().contains("Error checking status list"));

        verify(httpClient, times(1)).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));
        verify(httpClient, never()).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
        verify(httpClient, never()).execute(any(HttpPatch.class), any(HttpClientResponseHandler.class));
    }

    private StatusListService.StatusListPayload createTestPayload() {
        return new StatusListService.StatusListPayload(
                "test-list-id",
                List.of(new StatusListService.StatusListPayload.StatusEntry(1, "VALID"))
        );
    }
}
