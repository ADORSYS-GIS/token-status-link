package com.adorsys.keycloakstatuslist.model;

/**
 * Represents the possible states of a token or credential.
 */
public enum TokenStatus {
    /**
     * The token is active and can be used for authentication.
     */
    ACTIVE,

    /**
     * The token has been revoked by the user or administrator.
     */
    REVOKED,

    /**
     * The token has expired and can no longer be used.
     */
    EXPIRED,

    /**
     * The token is temporarily suspended and cannot be used.
     */
    SUSPENDED
}