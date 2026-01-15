package com.adorsys.keycloakstatuslist.model;

public enum TokenStatus {
    VALID(0),
    REVOKED(1);

    private final int value;

    TokenStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
