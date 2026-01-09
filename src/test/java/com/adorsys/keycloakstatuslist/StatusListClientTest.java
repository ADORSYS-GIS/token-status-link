package com.adorsys.keycloakstatuslist;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.adorsys.keycloakstatuslist.client.StatusListClient;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.model.TokenStatusRecord;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class StatusListClientTest {

    private StatusListClient client;

    @Mock
    private StatusListService statusListService;

    @BeforeEach
    void setUp() {
        statusListService = mock(StatusListService.class);
        client = new StatusListClient(statusListService);
    }

    @Test
    void testPublishRecordServerError() throws Exception {
        // Given
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId("token123");
        record.setIssuerId("test-issuer");
        doThrow(new StatusListException("Server Error"))
                .when(statusListService)
                .publishRecord(any(TokenStatusRecord.class));

        // When
        boolean result = client.publishRecord(record);

        // Then
        assertFalse(result);
        verify(statusListService).publishRecord(record);
    }

    @Test
    void testPublishRecordNetworkError() throws Exception {
        // Given
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId("token123");
        record.setIssuerId("test-issuer");
        doThrow(new StatusListException("Network error"))
                .when(statusListService)
                .publishRecord(any(TokenStatusRecord.class));

        // When
        boolean result = client.publishRecord(record);

        // Then
        assertFalse(result);
        verify(statusListService).publishRecord(record);
    }

    @Test
    void testValidateStatusRecordMissingRequiredFields() {
        // Create a token status record with missing required fields
        TokenStatusRecord record = new TokenStatusRecord();

        // Test missing credentialId
        Exception exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            client.publishRecord(record);
                        });
        assertTrue(exception.getMessage().contains("Credential ID (sub) is required"));

        // Test missing issuerId
        record.setCredentialId("token123");
        exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            client.publishRecord(record);
                        });
        assertTrue(exception.getMessage().contains("Issuer ID (iss) is required"));
    }

    @Test
    void testRevokedTokenValidation() throws Exception {
        // Given
        TokenStatusRecord record = new TokenStatusRecord();
        record.setCredentialId("token123");
        record.setIssuerId("test-issuer");
        record.setStatus(TokenStatus.REVOKED);
        doNothing().when(statusListService).publishRecord(any(TokenStatusRecord.class));

        // When
        boolean result = client.publishRecord(record);

        // Then
        assertTrue(result);
        verify(statusListService).publishRecord(record);
    }
}
