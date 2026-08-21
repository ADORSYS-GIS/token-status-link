package io.github.adorsysgis.keycloakstatuslist.exception;

import org.apache.hc.core5.http.HttpStatus;

public class StatusListException extends Exception {
    private int httpStatus;

    public StatusListException(String message) {
        super(message);
        this.httpStatus = HttpStatus.SC_INTERNAL_SERVER_ERROR;
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = HttpStatus.SC_INTERNAL_SERVER_ERROR;
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
