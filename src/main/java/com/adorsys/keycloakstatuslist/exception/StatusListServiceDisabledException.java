package com.adorsys.keycloakstatuslist.exception;

/**
 * Exception thrown when the status list service is disabled.
 */
public class StatusListServiceDisabledException extends StatusListException {

    public StatusListServiceDisabledException(String message) {
        super(message);
    }
}
