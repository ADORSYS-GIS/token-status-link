package com.adorsys.keycloakstatuslist.exception;

/**
 * Exception thrown when communication with the status list server fails.
 */
public class StatusListCommunicationException extends StatusListException {

    private final int statusCode;


    public StatusListCommunicationException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = 0;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
