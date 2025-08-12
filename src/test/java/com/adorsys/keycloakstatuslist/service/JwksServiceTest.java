package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.MockedStatic;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwksService.
 */
@ExtendWith(MockitoExtension.class)
class JwksServiceTest {

    @Mock
    private SdJwtVP sdJwtVP;
    
    @Mock
    private HttpClient httpClient;
    
    @Mock
    private HttpResponse<String> httpResponse;

    private JwksService service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        service = new JwksService();
    }

    @Test
    void testGetAllIssuerPublicKeys_KeycloakRealm() throws Exception {
        String issuer = "http://localhost:8080/realms/master";
        String requestId = "test-request-id";
        
        // Mock HTTP response with valid JWKS
        String jwksResponse = createValidJwksResponse();
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_StandardIssuer() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with valid JWKS
        String jwksResponse = createValidJwksResponse();
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_IssuerWithTrailingSlash() throws Exception {
        String issuer = "https://test-issuer.com/";
        String requestId = "test-request-id";
        
        // Mock HTTP response with valid JWKS
        String jwksResponse = createValidJwksResponse();
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_HttpError() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with error
        when(httpResponse.statusCode()).thenReturn(404);
        when(httpResponse.body()).thenReturn("Not Found");
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch JWKS from issuer"));
            assertTrue(exception.getMessage().contains("Status: 404"));
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_InvalidJwksFormat() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with invalid JSON
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("invalid json");
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch or parse issuer JWKS"));
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_NoKeys() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with JWKS but no keys
        String jwksResponse = "{\"keys\": []}";
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_MissingKty() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with JWKS but missing kty field
        String jwksResponse = "{\"keys\": [{\"kid\": \"test-key\"}]}";
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void testGetAllIssuerPublicKeys_UnsupportedKeyType() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP response with unsupported key type
        String jwksResponse = "{\"keys\": [{\"kty\": \"OCT\", \"kid\": \"test-key\"}]}";
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        // Mock HTTP client
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
            
            List<PublicKey> result = service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void testFindKeyByKid_Success() {
        JsonNode jwksJson = createValidJwksJson();
        String kid = "rsa-key-1";
        
        JsonNode result = service.findKeyByKid(jwksJson, kid);
        
        assertNotNull(result);
        assertEquals("RSA", result.get("kty").asText());
        assertEquals(kid, result.get("kid").asText());
    }

    @Test
    void testFindKeyByKid_NotFound() {
        JsonNode jwksJson = createValidJwksJson();
        String kid = "non-existent-key";
        
        JsonNode result = service.findKeyByKid(jwksJson, kid);
        
        assertNull(result);
    }

    @Test
    void testFindKeyByKid_NoKeys() {
        ObjectNode jwksJson = objectMapper.createObjectNode();
        jwksJson.putArray("keys");
        
        JsonNode result = service.findKeyByKid(jwksJson, "test-key");
        
        assertNull(result);
    }

    @Test
    void testExtractPublicKeyFromJwksKey_RSA() throws Exception {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        keyNode.put("n", "AQAB");
        keyNode.put("e", "AQAB");
        
        // This test data is intentionally invalid for RSA (too short), so we expect an exception
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });
        
        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_EC() throws Exception {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        keyNode.put("crv", "P-256");
        keyNode.put("x", "invalid-base64!");
        keyNode.put("y", "AQAB");
        
        // This test data is intentionally invalid (invalid Base64), so we expect an exception
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });
        
        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_UnsupportedType() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "UNSUPPORTED");
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });
        
        assertTrue(exception.getMessage().contains("Unsupported JWKS key type: UNSUPPORTED"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_MissingRsaParams() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "RSA");
        // Missing 'n' and 'e' parameters
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });
        
        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testExtractPublicKeyFromJwksKey_MissingEcParams() {
        ObjectNode keyNode = objectMapper.createObjectNode();
        keyNode.put("kty", "EC");
        // Missing 'crv', 'x', and 'y' parameters
        
        StatusListException exception = assertThrows(StatusListException.class, () -> {
            service.extractPublicKeyFromJwksKey(keyNode);
        });
        
        assertTrue(exception.getMessage().contains("Failed to extract public key from JWKS key node"));
    }

    @Test
    void testGetAllIssuerPublicKeys_NetworkException() throws Exception {
        String issuer = "https://test-issuer.com";
        String requestId = "test-request-id";
        
        // Mock HTTP client to throw exception
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new RuntimeException("Network error"));
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.getAllIssuerPublicKeys(sdJwtVP, issuer, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch or parse issuer JWKS"));
        }
    }

    private String createValidJwksResponse() {
        return """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "rsa-key-1",
                        "n": "AQAB",
                        "e": "AQAB"
                    },
                    {
                        "kty": "EC",
                        "kid": "ec-key-1",
                        "crv": "P-256",
                        "x": "AQAB",
                        "y": "AQAB"
                    }
                ]
            }
            """;
    }

    private JsonNode createValidJwksJson() {
        try {
            return objectMapper.readTree(createValidJwksResponse());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test JWKS JSON", e);
        }
    }
} 
