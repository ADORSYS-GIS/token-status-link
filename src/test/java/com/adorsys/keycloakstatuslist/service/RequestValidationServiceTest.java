package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for RequestValidationService.
 */
@ExtendWith(MockitoExtension.class)
class RequestValidationServiceTest {

    private RequestValidationService service;

    @BeforeEach
    void setUp() {
        service = new RequestValidationService();
    }

    @Test
    void testValidateRevocationRequest_Success() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123",
                "User requested revocation"
        );

        // Act & Assert - should not throw exception
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_NullRequest() {
        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(null);
        });

        assertEquals("Revocation request cannot be null", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_NullCredentialId() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                null,
                "User requested revocation"
        );

        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(request);
        });

        assertEquals("Credential ID is required", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_EmptyCredentialId() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "",
                "User requested revocation"
        );

        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(request);
        });

        assertEquals("Credential ID is required", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_WhitespaceCredentialId() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "   ",
                "User requested revocation"
        );

        // Act & Assert
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(request);
        });

        assertEquals("Credential ID is required", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_BothFieldsNull() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                null,
                null
        );

        // Act & Assert 
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(request);
        });

        assertEquals("Credential ID is required", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_BothFieldsEmpty() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "",
                ""
        );

        // Act & Assert 
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.validateRevocationRequest(request);
        });

        assertEquals("Credential ID is required", exception.getMessage());
    }

    @Test
    void testValidateRevocationRequest_ValidWithNullReason() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123",
                null
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithEmptyReason() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123",
                ""
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithLongReason() {
        // Arrange
        String longReason = "a".repeat(300);
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123",
                longReason
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithSpecialCharacters() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123-with-special-chars!@#$%",
                "Reason with special chars: !@#$%^&*()"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithUnicode() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-123-üöä",
                "Reason with unicode: üöäéèê"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithNumbers() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-456",
                "Reason with numbers: 1234567890"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithHyphens() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test-credential-id-with-hyphens",
                "Reason with hyphens: user-requested-revocation"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithUnderscores() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test_credential_id_with_underscores",
                "Reason with underscores: user_requested_revocation"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithSpaces() {
        // Arrange
        CredentialRevocationRequest request = new CredentialRevocationRequest(
                "test credential id with spaces",
                "Reason with spaces: user requested revocation"
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }

    @Test
    void testValidateRevocationRequest_ValidWithVeryLongValues() {
        // Arrange
        String longCredentialId = "b".repeat(1000);
        String longReason = "c".repeat(500);

        CredentialRevocationRequest request = new CredentialRevocationRequest(
                longCredentialId,
                longReason
        );

        // Act & Assert 
        assertDoesNotThrow(() -> {
            service.validateRevocationRequest(request);
        });
    }
} 
