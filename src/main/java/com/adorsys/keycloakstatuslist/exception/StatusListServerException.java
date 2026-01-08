package com.adorsys.keycloakstatuslist.exception;

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
