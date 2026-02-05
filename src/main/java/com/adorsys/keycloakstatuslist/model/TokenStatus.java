package com.adorsys.keycloakstatuslist.model;

public enum TokenStatus {
    VALID("VALID"),
    INVALID("INVALID");

    private final String value;

    TokenStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
