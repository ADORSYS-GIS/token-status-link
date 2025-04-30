package com.adorsys.keycloakstatuslist.exception;

/**
 * Exception thrown when the status list server returns an error.
 */
public class StatusListServerException extends StatusListException {

    private final int statusCode;

    public StatusListServerException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
