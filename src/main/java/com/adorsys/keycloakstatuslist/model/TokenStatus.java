package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum TokenStatus {
    VALID("valid"),
    REVOKED("revoked"),
    SUSPENDED("suspended"),
    EXPIRED("expired");

    private final String value;

    TokenStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
