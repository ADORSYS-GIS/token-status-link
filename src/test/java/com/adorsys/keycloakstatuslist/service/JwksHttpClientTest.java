package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.MockedStatic;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwksHttpClient.
 */
@ExtendWith(MockitoExtension.class)
class JwksHttpClientTest {

    @Mock
    private HttpClient httpClient;
    
    @Mock
    private HttpResponse<String> httpResponse;

    private JwksHttpClient service;

    @BeforeEach
    void setUp() {
        service = new JwksHttpClient();
    }

    @Test
    void testBuildJwksUrl_KeycloakRealm() {
        String issuer = "http://localhost:8080/realms/master";
        String expected = "http://localhost:8080/realms/master/protocol/openid-connect/certs";
        
        String result = service.buildJwksUrl(issuer);
        
        assertEquals(expected, result);
    }

    @Test
    void testBuildJwksUrl_StandardIssuer() {
        String issuer = "https://test-issuer.com";
        String expected = "https://test-issuer.com/.well-known/jwks.json";
        
        String result = service.buildJwksUrl(issuer);
        
        assertEquals(expected, result);
    }

    @Test
    void testBuildJwksUrl_IssuerWithTrailingSlash() {
        String issuer = "https://test-issuer.com/";
        String expected = "https://test-issuer.com/.well-known/jwks.json";
        
        String result = service.buildJwksUrl(issuer);
        
        assertEquals(expected, result);
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFetchJwks_Success() throws Exception {
        String jwksUrl = "https://test-issuer.com/.well-known/jwks.json";
        String requestId = "test-request-id";
        String jwksResponse = "{\"keys\": []}";
        
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(jwksResponse);
        
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            
            // Fix: Use proper generic types to eliminate warnings
            HttpResponse<String> mockResponse = (HttpResponse<String>) httpResponse;
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
            
            JsonNode result = service.fetchJwks(jwksUrl, requestId);
            
            assertNotNull(result);
            assertTrue(result.has("keys"));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFetchJwks_HttpError() throws Exception {
        String jwksUrl = "https://test-issuer.com/.well-known/jwks.json";
        String requestId = "test-request-id";
        
        when(httpResponse.statusCode()).thenReturn(404);
        when(httpResponse.body()).thenReturn("Not Found");
        
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            
            // Fix: Use proper generic types
            HttpResponse<String> mockResponse = (HttpResponse<String>) httpResponse;
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.fetchJwks(jwksUrl, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch JWKS from issuer (Status: 404)"));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFetchJwks_InvalidJson() throws Exception {
        String jwksUrl = "https://test-issuer.com/.well-known/jwks.json";
        String requestId = "test-request-id";
        
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("invalid json");
        
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            
            // Fix: Use proper generic types
            HttpResponse<String> mockResponse = (HttpResponse<String>) httpResponse;
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.fetchJwks(jwksUrl, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch JWKS"));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFetchJwks_EmptyResponse() throws Exception {
        String jwksUrl = "https://test-issuer.com/.well-known/jwks.json";
        String requestId = "test-request-id";
        
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("");
        
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            
            // Fix: Use proper generic types
            HttpResponse<String> mockResponse = (HttpResponse<String>) httpResponse;
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.fetchJwks(jwksUrl, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch JWKS"));
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFetchJwks_NetworkException() throws Exception {
        String jwksUrl = "https://test-issuer.com/.well-known/jwks.json";
        String requestId = "test-request-id";
        
        try (MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
            httpClientMock.when(HttpClient::newHttpClient).thenReturn(httpClient);
            
            // Fix: Use proper generic types and handle exceptions correctly
            when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new RuntimeException("Network error"));
            
            StatusListException exception = assertThrows(StatusListException.class, () -> {
                service.fetchJwks(jwksUrl, requestId);
            });
            
            assertTrue(exception.getMessage().contains("Failed to fetch JWKS"));
        }
    }
} 
