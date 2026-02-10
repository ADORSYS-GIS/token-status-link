package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.model.RevocationChallenge;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheProvider;
import com.adorsys.keycloakstatuslist.service.nonce.NonceCacheServiceProviderFactory;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

/**
 * REST resource for issuing nonce challenges for credential revocation.
 * Implements the first step of the secure 2-step revocation flow.
 */
public class RevocationChallengeResource {

    private static final Logger logger = Logger.getLogger(RevocationChallengeResource.class);

    private final KeycloakSession session;

    public RevocationChallengeResource(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Issues a nonce challenge for credential revocation.
     *
     * @return a RevocationChallengeResponse with nonce, audience, and expiration
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge() {
        try {
            // Build the expected audience (revocation endpoint URL)
            String audience = Urls.realmIssuer(
                    session.getContext().getUri().getBaseUri(),
                    session.getContext().getRealm().getName()) + "/protocol/openid-connect/revoke";

            // Get the nonce service provider via RealmResourceProvider
            logger.debugf("Attempting to get NonceCacheService from session");
            NonceCacheProvider nonceService = (NonceCacheProvider) session.getProvider(
                    RealmResourceProvider.class, NonceCacheServiceProviderFactory.PROVIDER_ID);
            if (nonceService == null) {
                logger.error("NonceCacheProvider not available - service not registered. ");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity(Map.of("error", "Nonce service not available"))
                        .build();
            }
            logger.debugf("Successfully obtained NonceCacheProvider instance");

            // Issue the nonce
            RevocationChallenge challenge = nonceService.issueNonce(audience);
            logger.infof("Issued revocation challenge. nonce: %s", challenge.getNonce());

            return Response.ok(challenge).build();

        } catch (Exception e) {
            logger.errorf(e, "Failed to issue revocation challenge");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "Failed to issue challenge: " + e.getMessage()))
                    .build();
        }
    }
}
