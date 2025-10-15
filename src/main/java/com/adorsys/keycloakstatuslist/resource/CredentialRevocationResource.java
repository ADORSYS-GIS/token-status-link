package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.TokenRevocationEndpoint;

public class CredentialRevocationResource extends TokenRevocationEndpoint {

    private static final Logger logger = Logger.getLogger(CredentialRevocationResource.class);

    private final KeycloakSession session;
    private final CredentialRevocationService revocationService;

    @Context
    private HttpHeaders headers;

    public CredentialRevocationResource(KeycloakSession session) {
        super(session, new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection()));
        this.session = session;
        this.revocationService = new CredentialRevocationService(session);
    }

    @POST
    @Override
    public Response revoke() {
        MultivaluedMap<String, String> form = session.getContext().getHttpRequest().getDecodedFormParameters();
        String authorizationHeader = headers.getHeaderString(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("bearer ")) {
            String token = authorizationHeader.substring("bearer ".length()).trim();
            String credentialId = form.getFirst("token");

            if (credentialId != null && !credentialId.isEmpty()) {
                logger.infof("Attempting credential revocation via SD-JWT VP for credentialId: %s", credentialId);
                try {
                    CredentialRevocationRequest request = new CredentialRevocationRequest();
                    request.setCredentialId(credentialId);
                    request.setRevocationReason(form.getFirst("reason"));

                    revocationService.revokeCredential(request, token);
                    logger.infof("Successfully revoked credential '%s' via status list.", credentialId);

                    return super.revoke();

                } catch (Exception e) {
                    logger.errorf(e, "SD-JWT VP based revocation failed for credentialId: %s. Falling back to standard revocation.", credentialId);
                }
            }
        }

        return super.revoke();
    }
}