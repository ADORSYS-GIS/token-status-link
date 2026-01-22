package com.adorsys.keycloakstatuslist.util;

/**
 * HTTP status code constants.
 */
public enum HttpStatusCode {
    OK(200),
    CREATED(201),
    NO_CONTENT(204),
    SUCCESS_MAX(299),
    NOT_FOUND(404),
    CONFLICT(409);

    private final int code;

    HttpStatusCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
    
    /**
     * Checks if the HTTP status code indicates a successful response (2xx range).
     *
     * @param statusCode the HTTP status code to check
     * @return true if the status code is in the 200-299 range, false otherwise
     */
    public static boolean isSuccess(int statusCode) {
        return statusCode >= OK.getCode() && statusCode <= SUCCESS_MAX.getCode();
    }
}
