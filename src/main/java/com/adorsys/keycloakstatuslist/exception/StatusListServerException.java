package com.adorsys.keycloakstatuslist.exception;

/**
 * Exception thrown when the status list server returns an error response.
 * This is an unchecked exception to allow direct propagation from HTTP response handlers
 * without unnecessary wrapping.
 */
public class StatusListServerException extends RuntimeException {
    private final int statusCode;

    public StatusListServerException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
