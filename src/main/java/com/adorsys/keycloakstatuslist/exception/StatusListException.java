package com.adorsys.keycloakstatuslist.exception;

public class StatusListException extends Exception {
    public StatusListException(String message) {
        super(message);
    }

    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}