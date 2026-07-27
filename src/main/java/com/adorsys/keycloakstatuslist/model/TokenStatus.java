package com.adorsys.keycloakstatuslist.model;

public enum TokenStatus {
    VALID("VALID", 0),
    INVALID("INVALID", 1);

    private final String value;
    private final int code;

    TokenStatus(String value, int code) {
        this.value = value;
        this.code = code;
    }

    public String getValue() {
        return value;
    }

    public int getCode() {
        return code;
    }

    public static TokenStatus fromValue(String value) {
        for (TokenStatus tokenStatus : values()) {
            if (tokenStatus.value.equals(value)) {
                return tokenStatus;
            }
        }

        throw new IllegalArgumentException("Unsupported token status: " + value);
    }
}
