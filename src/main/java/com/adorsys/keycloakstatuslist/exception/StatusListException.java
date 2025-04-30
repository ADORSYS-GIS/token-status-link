package com.adorsys.keycloakstatuslist.exception;

/**
 * Base exception class for all status list related exceptions.
 */
public class StatusListException extends Exception {

    public StatusListException(String message) {
        super(message);
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
