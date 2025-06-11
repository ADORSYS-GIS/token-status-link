package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.exception.StatusListServerException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class StatusListServiceTest {

    private static final String SERVER_URL = "https://status-list-server.adorsys.com";
    private static final String ISSUER_ID = "test-issuer";
    private static final String PUBLIC_KEY = "test-public-key";
    private static final String ALGORITHM = "RS256";
    private static final int RETRY_COUNT = 3;

    @Mock
    private HttpClient httpClient;

    @Mock
    private HttpResponse<String> httpResponse;

    @Mock
    private HttpHeaders httpHeaders;

    private StatusListService statusListService;

    @BeforeEach
    void setUp() {
        statusListService = new StatusListService(SERVER_URL, null, httpClient, RETRY_COUNT) {
            @Override
            protected void performSleep(long millis) throws InterruptedException {
            }
        };
    }

    private void setupResponse(int statusCode, String body) throws IOException, InterruptedException {
        when(httpResponse.headers()).thenReturn(httpHeaders);
        when(httpHeaders.toString()).thenReturn("{}");
        when(httpResponse.statusCode()).thenReturn(statusCode);
        when(httpResponse.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(httpResponse);
    }

    private void setupSuccessfulResponse() throws IOException, InterruptedException {
        setupResponse(200, "{}");
    }

    private void setupResponseWithStatus(int statusCode) throws IOException, InterruptedException {
        setupResponse(statusCode, "{}");
    }

    private void setupRetryResponse(Exception exception) throws IOException, InterruptedException {
        when(httpResponse.headers()).thenReturn(httpHeaders);
        when(httpHeaders.toString()).thenReturn("{}");
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(exception)
                .thenReturn(httpResponse);
    }


    private void verifyHttpClientCall(int expectedCalls) throws IOException, InterruptedException {
        verify(httpClient, times(expectedCalls)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void successScenarios() throws IOException, InterruptedException {
        // Test register issuer success
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        verifyHttpClientCall(1);

        // Test publish record success
        reset(httpClient);
        final TokenStatusRecord record = createTestRecord();
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test publish record with auth token
        reset(httpClient);
        statusListService = new StatusListService(SERVER_URL, "test-token", httpClient, RETRY_COUNT);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);
    }

    @Test
    void retryScenarios() throws IOException, InterruptedException {
        final TokenStatusRecord record = createTestRecord();

        // Test retry on connect exception for register
        setupRetryResponse(new ConnectException("Connection refused"));
        assertDoesNotThrow(() -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        verifyHttpClientCall(2);

        // Test retry on timeout for register
        reset(httpClient);
        setupRetryResponse(new HttpTimeoutException("Request timed out"));
        assertDoesNotThrow(() -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        verifyHttpClientCall(2);

        // Test retry on connect exception for publish
        reset(httpClient);
        setupRetryResponse(new ConnectException("Connection refused"));
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(2);

        // Test retry on timeout for publish
        reset(httpClient);
        setupRetryResponse(new HttpTimeoutException("Request timed out"));
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(2);
    }

    @Test
    void responseBodyScenarios() throws IOException, InterruptedException {
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
    void registerIssuer_AlreadyRegistered() throws IOException, InterruptedException {
        // Arrange
        setupResponseWithStatus(409);

        // Act & Assert
        assertDoesNotThrow(() -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        verifyHttpClientCall(1);
    }

    @Test
    void registerIssuer_MaxRetriesExceeded() throws IOException, InterruptedException {
        // Arrange
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new ConnectException("Connection refused"))
                .thenThrow(new ConnectException("Connection refused"))
                .thenThrow(new ConnectException("Connection refused"))
                .thenThrow(new ConnectException("Connection refused"));

        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class,
                () -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        
        // Verify the exception message contains the expected text
        assertTrue(exception.getMessage().contains("Failed to register issuer: " + ISSUER_ID));
        assertTrue(exception.getMessage().contains("Server URL: " + SERVER_URL));
        
        // Verify the number of retry attempts
        verify(httpClient, times(RETRY_COUNT + 1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void registerIssuer_ServerError() throws IOException, InterruptedException {
        // Arrange
        setupResponseWithStatus(500);

        // Act & Assert
        StatusListServerException exception = assertThrows(StatusListServerException.class,
                () -> statusListService.registerIssuer(ISSUER_ID, PUBLIC_KEY, ALGORITHM));
        assertEquals(500, exception.getStatusCode());
        verifyHttpClientCall(1);
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

        // Test missing algorithm
        final TokenStatusRecord record4 = createTestRecord();
        record4.setAlg(null);
        exception = assertThrows(StatusListException.class,
                () -> statusListService.publishRecord(record4));
        assertTrue(exception.getMessage().contains("Algorithm (alg) is required"));
    }

    @Test
    void publishRecord_DefaultValues() throws IOException, InterruptedException {
        // Test default status
        final TokenStatusRecord record1 = createTestRecord();
        record1.setStatus(TokenStatus.REVOKED);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record1));
        assertEquals(TokenStatus.REVOKED.getValue(), record1.getStatus());
        verifyHttpClientCall(1);

        // Test default credential type
        reset(httpClient);
        final TokenStatusRecord record2 = createTestRecord();
        record2.setCredentialType(null);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record2));
        assertEquals("oauth2", record2.getCredentialType());
        verifyHttpClientCall(1);
    }

    @Test
    void publishRecord_StatusCodeHandling() throws IOException, InterruptedException {
        TokenStatusRecord record = createTestRecord();

        // Test 200 OK
        setupResponseWithStatus(200);
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test 201 Created
        reset(httpClient);
        setupResponseWithStatus(201);
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test 204 No Content
        reset(httpClient);
        setupResponseWithStatus(204);
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test 409 Conflict (already registered)
        reset(httpClient);
        setupResponseWithStatus(409);
        assertDoesNotThrow(() -> statusListService.publishRecord(record));
        verifyHttpClientCall(1);

        // Test 400 Bad Request
        reset(httpClient);
        setupResponseWithStatus(400);
        StatusListServerException exception = assertThrows(StatusListServerException.class,
                () -> statusListService.publishRecord(record));
        assertEquals(400, exception.getStatusCode());
        verifyHttpClientCall(1);
    }

    @Test
    void publishRecord_RecordFieldHandling() throws IOException, InterruptedException {
        // Test issuer field is set from issuerId
        final TokenStatusRecord record1 = createTestRecord();
        record1.setIssuer(null);
        record1.setIssuerId(ISSUER_ID);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record1));
        assertEquals(ISSUER_ID, record1.getIssuer());
        verifyHttpClientCall(1);

        // Test index field is set to null when 0
        reset(httpClient);
        final TokenStatusRecord record2 = createTestRecord();
        record2.setIndex(0L);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record2));
        assertNull(record2.getIndex());
        verifyHttpClientCall(1);

        // Test status field default value
        reset(httpClient);
        final TokenStatusRecord record3 = createTestRecord();
        record3.setStatus(TokenStatus.REVOKED);
        setupSuccessfulResponse();
        assertDoesNotThrow(() -> statusListService.publishRecord(record3));
        assertEquals(TokenStatus.REVOKED.getValue(), record3.getStatus());
        verifyHttpClientCall(1);
    }

    private TokenStatusRecord createTestRecord() {
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId(UUID.randomUUID().toString());
        record.setIssuer(ISSUER_ID);
        record.setIssuerId(ISSUER_ID);
        record.setPublicKey(PUBLIC_KEY);
        record.setAlg(ALGORITHM);
        record.setStatus(TokenStatus.VALID);
        record.setIssuedAt(Instant.now());
        record.setExpiresAt(Instant.now().plusSeconds(3600));
        return record;
    }
} 
