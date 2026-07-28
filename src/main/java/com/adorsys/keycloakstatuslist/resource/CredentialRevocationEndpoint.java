package com.adorsys.keycloakstatuslist.resource;

import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.CREDENTIAL_ID_KEY;
import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.ISSUED_CREDENTIAL_REVOCATION_MODE;
import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_MODE_KEY;
import static com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest.REVOCATION_REASON_KEY;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationRequest;
import com.adorsys.keycloakstatuslist.model.CredentialRevocationResponse;
import com.adorsys.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.endpoints.TokenRevocationEndpoint;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.utils.StringUtil;

public class CredentialRevocationEndpoint extends TokenRevocationEndpoint {

    private static final Logger logger = Logger.getLogger(CredentialRevocationEndpoint.class);
    private static final String BEARER_PREFIX = "bearer";

    private final KeycloakSession session;
    private final CredentialRevocationService revocationService;
    private final HttpHeaders headers;

    /**
     * Constructor with dependency injection for better testability.
     *
     * @param session           Keycloak session
     * @param event             EventBuilder for logging
     * @param revocationService Credential revocation service (can be injected for testing)
     */
    public CredentialRevocationEndpoint(
            KeycloakSession session, EventBuilder event, CredentialRevocationService revocationService) {
        super(session, event);
        this.session = session;
        this.revocationService = revocationService;
        this.headers = session.getContext().getRequestHeaders();
    }

    @Override
    public Response revoke() {
        MultivaluedMap<String, String> form =
                session.getContext().getHttpRequest().getDecodedFormParameters();
        String authorizationHeader = getHeaders().getHeaderString(HttpHeaders.AUTHORIZATION);
        String revocationMode = form.getFirst(REVOCATION_MODE_KEY);

        if (!ISSUED_CREDENTIAL_REVOCATION_MODE.equals(revocationMode)) {
            logger.debugf("Not in credential revocation mode. Falling back to standard revocation logic.");
            return super.revoke();
        }

        if (!isServiceEnabled()) {
            logger.debug("Will fail because credential revocation service is disabled");
            // In a RealmResourceProvider, we don't have a super.revoke().
            // We should return an error or handle it differently.
            return createErrorResponse(
                    Response.Status.INTERNAL_SERVER_ERROR, "Credential revocation service is disabled");
        }

        if (!isServiceConfigured()) {
            logger.warn("Will fail because credential revocation service is not configured");
            return createErrorResponse(
                    Response.Status.INTERNAL_SERVER_ERROR, "Credential revocation service is not configured");
        }

        if (authorizationHeader == null || authorizationHeader.trim().isEmpty()) {
            logger.debug("No authorization header provided, returning error for custom revocation");
            return createErrorResponse(Response.Status.UNAUTHORIZED, "Missing Authorization header");
        }

        String[] authParts = authorizationHeader.trim().split("\\s+", 2);
        if (authParts.length != 2 || !BEARER_PREFIX.equalsIgnoreCase(authParts[0])) {
            logger.debugf("Invalid authorization header format: %s, returning error", authorizationHeader);
            return createErrorResponse(Response.Status.BAD_REQUEST, "Invalid authorization header format");
        }

        String token = authParts[1].trim();

        logger.infof("Attempting credential revocation via Token Status List. Mode: %s", revocationMode);

        try {
            CredentialRevocationRequest request = new CredentialRevocationRequest();
            request.setRevocationMode(revocationMode);
            request.setRevocationReason(form.getFirst(REVOCATION_REASON_KEY));
            request.setCredentialId(form.getFirst(CREDENTIAL_ID_KEY));

            AuthResult authResult = authenticateBearerToken(token);
            if (authResult == null || authResult.user() == null) {
                return createErrorResponse(Response.Status.UNAUTHORIZED, "Invalid bearer token");
            }
            CredentialRevocationResponse revocationResponse =
                    getRevocationService().revokeIssuedCredential(request, authResult);
            logger.infof("Successfully revoked credential via status list.");

            return Response.ok(revocationResponse)
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (StatusListException e) {
            logger.errorf(e, "Credential revocation failed due to status list error. Mode: %s", revocationMode);
            int statusCode = e.getHttpStatus();
            return Response.status(statusCode)
                    .entity(CredentialRevocationResponse.error(e.getMessage()))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Credential revocation failed due to invalid input. Mode: %s", revocationMode);
            return createErrorResponse(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.errorf(e, "Credential revocation failed due to unexpected error. Mode: %s", revocationMode);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(
                            "{\"error\":\"server_error\",\"error_description\":\"Internal error during credential revocation\"}")
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }

    /**
     * Gets the HTTP headers, handling both injected and constructor-provided
     * headers. Made protected for testability.
     */
    protected HttpHeaders getHeaders() {
        if (headers == null) {
            throw new IllegalStateException(
                    "HttpHeaders not properly injected via @Context for standard revocation endpoint");
        }
        return headers;
    }

    /**
     * Gets the revocation service, handling both injected and constructor-provided
     * services. Made protected for testability.
     */
    protected CredentialRevocationService getRevocationService() {
        return revocationService;
    }

    /**
     * Authenticates a standard Keycloak bearer access token. Made protected for testability.
     */
    protected AuthResult authenticateBearerToken(String token) {
        return new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(session.getContext().getRealm())
                .setUriInfo(session.getContext().getUri())
                .setConnection(session.getContext().getConnection())
                .setHeaders(getHeaders())
                .setRequest(session.getContext().getHttpRequest())
                .setTokenString(token)
                .authenticate();
    }

    /**
     * Checks if the credential revocation service is enabled for the current realm.
     */
    private boolean isServiceEnabled() {
        try {
            StatusListConfig config = new StatusListConfig(session.getContext().getRealm());
            return config.isEnabled();
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
            return config.isEnabled() && StringUtil.isNotBlank(config.getServerUrl());

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
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
