package com.adorsys.keycloakstatuslist.exception;

/**
 * Exception thrown for errors related to the Status List service operations.
 * This replaces the boolean return values for more robust error handling.
 */
public class StatusListException extends Exception {
    
    /**
     * Creates a new StatusListException with the specified detail message.
     *
     * @param message The detail message
     */
    public StatusListException(String message) {
        super(message);
    }
    
    /**
     * Creates a new StatusListException with the specified detail message and cause.
     *
     * @param message The detail message
     * @param cause The cause of the exception
     */
    public StatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
