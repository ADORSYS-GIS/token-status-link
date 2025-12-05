package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;

import jakarta.ws.rs.Path;

/**
 * Custom extension of OIDCLoginProtocolService to override the /revoke sub-resource with credential-aware logic.
 * Compatible with OID4VC flows; preserves other endpoints.
 */
public class CustomOIDCLoginProtocolService extends OIDCLoginProtocolService {

    private final KeycloakSession session;

    public CustomOIDCLoginProtocolService(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.session = session;
    }

    @Override
    @Path("revoke")
    public Object revoke() {
        return new CredentialRevocationResource(this.session);
    }
}