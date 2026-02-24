package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
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
    private final CredentialRevocationService revocationService;

    public CustomOIDCLoginProtocolService(
            KeycloakSession session,
            EventBuilder event,
            CredentialRevocationService revocationService
    ) {
        super(session, event);
        this.session = session;
        this.event = event;
        this.revocationService = revocationService;
    }

    @Override
    public Object revoke() {
        return new CredentialRevocationEndpoint(
                this.session,
                this.event,
                this.revocationService
        );
    }
}
