package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.RevocationChallengeResponse;
import com.adorsys.keycloakstatuslist.service.NonceCacheProvider;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.Urls;

import java.util.Map;

/**
 * REST resource for issuing nonce challenges for credential revocation.
 * Implements the first step of the secure 2-step revocation flow.
 * 
 * Flow:
 * 1. Wallet calls POST /revoke/challenge with credential_id
 * 2. Server generates and returns a fresh nonce with audience and expiration
 * 3. Wallet creates SD-JWT VP with Key Binding JWT containing the nonce
 * 4. Wallet calls POST /revoke with the VP
 */
@Path("/revoke/challenge")
public class RevocationChallengeResource {
    
    private static final Logger logger = Logger.getLogger(RevocationChallengeResource.class);
    private static final int NONCE_EXPIRATION_SECONDS = 600; // 10 minutes
    
    private final KeycloakSession session;
    
    public RevocationChallengeResource(KeycloakSession session) {
        this.session = session;
    }
    
    /**
     * Issues a nonce challenge for credential revocation.
     * 
     * @param request the revocation request containing credential_id
     * @return a RevocationChallengeResponse with nonce, audience, and expiration
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge(CredentialRevocationRequest request) {
        try {
            // Validate request
            if (request == null || request.getCredentialId() == null || request.getCredentialId().isBlank()) {
                logger.warn("Challenge request missing credential_id");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error", "credential_id required"))
                        .build();
            }
            
            String credentialId = request.getCredentialId();
            
            // Build the expected audience (revocation endpoint URL)
            String audience = Urls.realmIssuer(
                session.getContext().getUri().getBaseUri(),
                session.getContext().getRealm().getName()
            ) + "/protocol/openid-connect/revoke";
            
            // Get the nonce service provider via RealmResourceProvider
            logger.debugf("Attempting to get NonceCacheService from session");
            NonceCacheProvider nonceService = (NonceCacheProvider) session.getProvider(
                org.keycloak.services.resource.RealmResourceProvider.class, 
                "nonce-cache"
            );
            if (nonceService == null) {
                logger.error("NonceCacheProvider not available - service not registered. " +
                           "Check that the plugin JAR contains META-INF/services/" +
                           "org.keycloak.services.resource.RealmResourceProviderFactory " +
                           "with NonceCacheServiceProviderFactory");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity(Map.of("error", "Nonce service not available"))
                        .build();
            }
            logger.debugf("Successfully obtained NonceCacheProvider instance");
            
            // Issue the nonce
            String nonce = nonceService.issueNonce(credentialId, audience);
            
            logger.infof("Issued revocation challenge for credential: %s, nonce: %s", credentialId, nonce);
            
            // Return the challenge response
            RevocationChallengeResponse response = new RevocationChallengeResponse(
                nonce,
                audience,
                NONCE_EXPIRATION_SECONDS
            );
            
            return Response.ok(response).build();
            
        } catch (Exception e) {
            logger.errorf(e, "Failed to issue revocation challenge");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to issue challenge: " + e.getMessage()))
                    .build();
        }
    }
}

