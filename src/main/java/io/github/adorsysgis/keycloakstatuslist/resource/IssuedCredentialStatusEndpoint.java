package io.github.adorsysgis.keycloakstatuslist.resource;

import io.github.adorsysgis.keycloakstatuslist.model.CredentialRevocationResponse;
import io.github.adorsysgis.keycloakstatuslist.model.IssuedCredentialStatusResponse;
import io.github.adorsysgis.keycloakstatuslist.service.CredentialRevocationService;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

public class IssuedCredentialStatusEndpoint {

    private static final Logger logger = Logger.getLogger(IssuedCredentialStatusEndpoint.class);

    private final KeycloakSession session;
    private final CredentialRevocationService credentialRevocationService;

    public IssuedCredentialStatusEndpoint(
            KeycloakSession session, CredentialRevocationService credentialRevocationService) {
        this.session = session;
        this.credentialRevocationService = credentialRevocationService;
    }

    @OPTIONS
    @Produces(MediaType.APPLICATION_JSON)
    public Response preflight() {
        return createPreflightResponse();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getIssuedCredentialStatuses() {
        try {
            AuthResult authResult = authenticateBearerToken();
            if (authResult == null || authResult.user() == null) {
                return createErrorResponse(Response.Status.UNAUTHORIZED, "Invalid bearer token");
            }

            IssuedCredentialStatusResponse statusResponse =
                    credentialRevocationService.getIssuedCredentialStatuses(authResult);

            return addCors(authResult, Response.ok(statusResponse).type(MediaType.APPLICATION_JSON));
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Issued credential status lookup failed due to invalid input");
            return createErrorResponse(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.errorf(e, "Issued credential status lookup failed due to unexpected error");
            return createErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Internal error during status lookup");
        }
    }

    protected AuthResult authenticateBearerToken() {
        return new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    protected Response createPreflightResponse() {
        return Cors.builder().allowedMethods(HttpMethod.GET).preflight().auth().add(Response.ok());
    }

    protected Response addCors(AuthResult authResult, Response.ResponseBuilder responseBuilder) {
        return Cors.builder()
                .auth()
                .checkAllowedOrigins(session, authResult.client())
                .add(responseBuilder);
    }

    private Response createErrorResponse(Response.Status status, String message) {
        return Response.status(status)
                .entity(CredentialRevocationResponse.error(message))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
