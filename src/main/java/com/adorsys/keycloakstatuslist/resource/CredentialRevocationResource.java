package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.TokenRevocationEndpoint;

public class CredentialRevocationResource extends TokenRevocationEndpoint {

    private static final Logger logger = Logger.getLogger(CredentialRevocationResource.class);
    private static final String BEARER_PREFIX = "bearer";

    private final KeycloakSession session;
    private final CredentialRevocationService revocationService;
    private HttpHeaders headers;

    /**
     * Constructor with dependency injection for better testability.
     *
     * @param session Keycloak session
     * @param headers HTTP headers (can be injected via @Context)
     * @param revocationService Credential revocation service (can be injected for testing)
     */
    public CredentialRevocationResource(KeycloakSession session, HttpHeaders headers, CredentialRevocationService revocationService) {
        super(session, createEventBuilder(session));
        this.session = session;
        this.headers = headers;
        this.revocationService = revocationService;
    }

    /**
     * Default constructor for Keycloak resource instantiation.
     * Uses field injection for HttpHeaders and creates default service.
     */
    public CredentialRevocationResource(KeycloakSession session) {
        super(session, createEventBuilder(session));
        this.session = session;
        this.headers = null; // Will be injected via @Context
        this.revocationService = new CredentialRevocationService(session);
    }

    @Context
    public void setHeaders(HttpHeaders headers) {
        this.headers = headers;
    }

    /**
     * Creates an EventBuilder for the parent class.
     * Extracted to a helper method for clarity and reusability.
     */
    private static EventBuilder createEventBuilder(KeycloakSession session) {
        return new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection());
    }

    @POST
    @Override
    public Response revoke() {
        MultivaluedMap<String, String> form = session.getContext().getHttpRequest().getDecodedFormParameters();
        String authorizationHeader = getHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || authorizationHeader.trim().isEmpty()) {
            logger.debug("No authorization header provided, falling back to standard revocation");
            return super.revoke();
        }

        String[] authParts = authorizationHeader.trim().split("\\s+", 2);
        if (authParts.length != 2 || !BEARER_PREFIX.equalsIgnoreCase(authParts[0])) {
            logger.debugf("Invalid authorization header format: %s, falling back to standard revocation", authorizationHeader);
            return super.revoke();
        }

        String token = authParts[1].trim();
        String credentialId = form.getFirst("token");

        if (credentialId == null || credentialId.trim().isEmpty()) {
            logger.warn("Valid Bearer provided but no credential ID in form; returning error for custom revocation");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"invalid_request\",\"error_description\":\"Missing credential ID\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        logger.infof("Attempting credential revocation via SD-JWT VP for credentialId: %s", credentialId);
        try {
            CredentialRevocationRequest request = new CredentialRevocationRequest();
            request.setCredentialId(credentialId);
            request.setRevocationReason(form.getFirst("reason"));

            getRevocationService().revokeCredential(request, token);
            logger.infof("Successfully revoked credential '%s' via status list.", credentialId);

            return Response.ok().build();

        } catch (StatusListException e) {
            logger.errorf(e, "SD-JWT VP based revocation failed for credentialId: %s due to status list error. Falling back to standard revocation.", credentialId);
            return super.revoke();
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "SD-JWT VP based revocation failed for credentialId: %s due to invalid input. Falling back to standard revocation.", credentialId);
            return super.revoke();
        } catch (Exception e) {
            logger.errorf(e, "SD-JWT VP based revocation failed for credentialId: %s due to unexpected error.", credentialId);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"Internal error during credential revocation\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }

    /**
     * Gets the HTTP headers, handling both injected and constructor-provided headers.
     * Made protected for testability.
     */
    protected HttpHeaders getHeaders() {
        if (headers == null) {
            throw new IllegalStateException("HttpHeaders not properly injected via @Context for standard revocation endpoint");
        }
        return headers;
    }

    /**
     * Gets the revocation service, handling both injected and constructor-provided services.
     * Made protected for testability.
     */
    protected CredentialRevocationService getRevocationService() {
        return revocationService;
    }
}