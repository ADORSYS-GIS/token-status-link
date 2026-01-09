package com.adorsys.keycloakstatuslist.exception;

public class StatusListException extends Exception {
    private int httpStatus;

    public StatusListException(String message) {
        super(message);
        this.httpStatus = 500; // Default to Internal Server Error
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = 500; // Default to Internal Server Error
    }

    public StatusListException(String message, int httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
    }

    public StatusListException(String message, Throwable cause, int httpStatus) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
