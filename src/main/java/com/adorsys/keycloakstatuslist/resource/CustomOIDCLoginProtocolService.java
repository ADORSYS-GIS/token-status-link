package com.adorsys.keycloakstatuslist.resource;

import jakarta.ws.rs.Path;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;

/**

 * Custom extension of OIDCLoginProtocolService to override the /revoke sub-resource with
 * credential-aware logic. Compatible with OID4VC flows; preserves other endpoints.
 */
public class CustomOIDCLoginProtocolService extends OIDCLoginProtocolService {

    private final KeycloakSession session;
    private final EventBuilder event;

    public CustomOIDCLoginProtocolService(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.session = session;
        this.event = event;
    }

    /**
     * Challenge endpoint that issues nonces for the revocation flow.
     * This is step 1 of the secure revocation flow.
     * IMPORTANT: This must come BEFORE the @Path("revoke") method for JAX-RS to match it correctly.
     */
    @Path("revoke/challenge")
    public Object revokeChallenge() {
        return new RevocationChallengeResource(this.session);
    }
    
    /**
     * Main revocation endpoint that processes SD-JWT VP based credential revocations.
     * This is step 2 of the secure revocation flow.
     */
    @Override
    @Path("revoke")
    public Object revoke() {
        return new CredentialRevocationResource(this.session, this.event);
    }
}
