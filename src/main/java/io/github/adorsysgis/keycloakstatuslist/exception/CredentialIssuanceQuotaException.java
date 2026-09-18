package io.github.adorsysgis.keycloakstatuslist.exception;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Client-facing failure when credential issuance quota rules block issuance.
 */
public class CredentialIssuanceQuotaException extends WebApplicationException {

    public static final String ERROR_LIMIT_REACHED = "credential_limit_reached";
    public static final String ERROR_FAIL_CLOSED = "credential_limit_unresolved";

    private final String error;
    private final String errorDescription;

    private CredentialIssuanceQuotaException(String error, String errorDescription, Response.Status status) {
        super(errorDescription, response(error, errorDescription, status));
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public static CredentialIssuanceQuotaException limitReached(String message) {
        return new CredentialIssuanceQuotaException(ERROR_LIMIT_REACHED, message, Response.Status.CONFLICT);
    }

    public static CredentialIssuanceQuotaException failClosed(String message) {
        return new CredentialIssuanceQuotaException(ERROR_FAIL_CLOSED, message, Response.Status.BAD_REQUEST);
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    private static Response response(String error, String errorDescription, Response.Status status) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", errorDescription);
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(body)
                .build();
    }
}
