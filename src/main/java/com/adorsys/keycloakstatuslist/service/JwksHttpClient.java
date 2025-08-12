package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

/**
 * HTTP client for fetching JWKS from issuer endpoints.
 * Handles URL construction and HTTP requests for JWKS retrieval.
 */
public class JwksHttpClient {
    
    private static final Logger logger = Logger.getLogger(JwksHttpClient.class);
    private final ObjectMapper objectMapper;
    
    public JwksHttpClient() {
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Constructs the appropriate JWKS URL based on the issuer type.
     */
    public String buildJwksUrl(String issuer) {
        if (issuer == null || issuer.trim().isEmpty()) {
            throw new IllegalArgumentException("Issuer cannot be null or empty");
        }
        
        String normalizedIssuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        
        if (normalizedIssuer.contains("/realms/")) {
            return normalizedIssuer + "/protocol/openid-connect/certs";
        } else {
            return normalizedIssuer + "/.well-known/jwks.json";
        }
    }
    
    /**
     * Fetches JWKS from the given URL and returns parsed JSON.
     */
    public JsonNode fetchJwks(String jwksUrl, String requestId) throws StatusListException {
        try {
            logger.debugf("Fetching JWKS from: %s. RequestId: %s", jwksUrl, requestId);
            
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(jwksUrl))
                    .header("Accept", "application/json")
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();

            if (statusCode >= 400) {
                logger.errorf("Failed to fetch JWKS from %s. Status: %d, Body: %s. RequestId: %s", 
                             jwksUrl, statusCode, response.body(), requestId);
                throw new StatusListException("Failed to fetch JWKS from issuer (Status: " + statusCode + ")");
            }

            JsonNode jwksJson = objectMapper.readTree(response.body());
            if (jwksJson == null || !jwksJson.isObject()) {
                logger.errorf("Invalid JWKS format from %s. RequestId: %s", jwksUrl, requestId);
                throw new StatusListException("Invalid JWKS format from issuer");
            }
            
            return jwksJson;
            
        } catch (Exception e) {
            logger.errorf("Failed to fetch JWKS from %s. RequestId: %s, Error: %s", jwksUrl, requestId, e.getMessage());
            throw new StatusListException("Failed to fetch JWKS: " + e.getMessage(), e);
        }
    }
} 
