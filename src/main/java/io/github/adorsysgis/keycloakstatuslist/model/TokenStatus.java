package io.github.adorsysgis.keycloakstatuslist.model;

public enum TokenStatus {
    VALID(0),
    INVALID(1),
    SUSPENDED(2);

    private final int code;

    TokenStatus(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
