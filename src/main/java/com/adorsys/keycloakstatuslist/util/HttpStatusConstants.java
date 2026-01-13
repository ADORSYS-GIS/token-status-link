package com.adorsys.keycloakstatuslist.util;

/**
 * HTTP status code constants.
 */
public final class HttpStatusConstants {
    private HttpStatusConstants() {
        // Utility class - prevent instantiation
    }

    public static final int OK = 200;
    public static final int CREATED = 201;
    public static final int NO_CONTENT = 204;
    public static final int NOT_FOUND = 404;
    public static final int CONFLICT = 409;
}
