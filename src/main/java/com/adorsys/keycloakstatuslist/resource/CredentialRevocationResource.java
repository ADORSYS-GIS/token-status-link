package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

/**
 * REST resource for credential revocation.
 * Provides endpoints for revoking credentials using SD-JWT VP tokens.
 */
@Path("/credential-revocation")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CredentialRevocationResource {
    
    private static final Logger logger = Logger.getLogger(CredentialRevocationResource.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private final KeycloakSession session;
    private final CredentialRevocationService revocationService;

    public CredentialRevocationResource(KeycloakSession session) {
        this.session = session;
        this.revocationService = new CredentialRevocationService(session);
    }

    /**
     * POST endpoint for revoking a credential.
     * 
     * @param requestBody JSON request body containing SD-JWT VP token and credential ID
     * @return Response with revocation result
     */
    @POST
    @Path("/revoke")
    public Response revokeCredential(String requestBody) {
        try {
            // Check if service is enabled
            if (!isServiceEnabled()) {
                return createErrorResponse(Response.Status.SERVICE_UNAVAILABLE, 
                                        "Credential revocation service is disabled");
            }
            
            // Check if service is properly configured
            if (!isServiceConfigured()) {
                return createErrorResponse(Response.Status.SERVICE_UNAVAILABLE, 
                                        "Credential revocation service is not properly configured");
            }
            
            // Parse request
            CredentialRevocationRequest request = parseRequest(requestBody);
            
            // Process revocation
            CredentialRevocationResponse response = revocationService.revokeCredential(request);
            
            return Response.ok(response).build();
            
        } catch (StatusListException e) {
            logger.error("Credential revocation failed", e);
            return createErrorResponse(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("Service configuration error", e);
            return createErrorResponse(Response.Status.SERVICE_UNAVAILABLE, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during credential revocation", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, 
                                    "Internal server error during credential revocation");
        }
    }

    /**
     * GET endpoint for checking service status.
     * 
     * @return Response indicating if the service is enabled and configured
     */
    @GET
    @Path("/status")
    public Response getServiceStatus() {
        try {
            boolean enabled = isServiceEnabled();
            boolean configured = isServiceConfigured();
            
            Map<String, Object> status = new HashMap<>();
            status.put("enabled", enabled);
            status.put("configured", configured);
            status.put("service", "credential-revocation");
            
            if (enabled && configured) {
                status.put("message", "Credential revocation service is available");
                return Response.ok(status).build();
            } else if (!enabled) {
                status.put("message", "Credential revocation service is disabled");
                return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(status).build();
            } else {
                status.put("message", "Credential revocation service is not properly configured");
                return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(status).build();
            }
            
        } catch (Exception e) {
            logger.error("Error checking service status", e);
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, 
                                    "Error checking service status");
        }
    }

    /**
     * Parses the JSON request body into a CredentialRevocationRequest object.
     */
    private CredentialRevocationRequest parseRequest(String requestBody) throws StatusListException {
        if (requestBody == null || requestBody.trim().isEmpty()) {
            throw new StatusListException("Request body is required");
        }
        
        try {
            return objectMapper.readValue(requestBody, CredentialRevocationRequest.class);
        } catch (Exception e) {
            throw new StatusListException("Invalid JSON request format: " + e.getMessage());
        }
    }

    /**
     * Checks if the credential revocation service is enabled for the current realm.
     */
    private boolean isServiceEnabled() {
        try {
            RealmModel realm = session.getContext().getRealm();
            String enabled = realm.getAttribute("status-list-enabled");
            return "true".equalsIgnoreCase(enabled);
        } catch (Exception e) {
            logger.warn("Error checking service status, defaulting to disabled", e);
            return false;
        }
    }

    /**
     * Checks if the credential revocation service is properly configured.
     */
    private boolean isServiceConfigured() {
        try {
            RealmModel realm = session.getContext().getRealm();
            StatusListConfig config = new StatusListConfig(realm);
            
            // Check if the service is enabled and has a valid server URL
            return config.isEnabled() && 
                   config.getServerUrl() != null && 
                   !config.getServerUrl().trim().isEmpty();
            
        } catch (Exception e) {
            logger.warn("Error checking service configuration", e);
            return false;
        }
    }

    /**
     * Creates a standardized error response using CredentialRevocationResponse.
     */
    private Response createErrorResponse(Response.Status status, String message) {
        return Response.status(status)
                .entity(CredentialRevocationResponse.error(message))
                .build();
    }
} 
