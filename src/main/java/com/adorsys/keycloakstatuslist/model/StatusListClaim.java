package com.adorsys.keycloakstatuslist.model;

public class StatusListClaim {
    private final String idx;
    private final String uri;

    public StatusListClaim(String idx, String uri) {
        this.idx = idx;
        this.uri = uri;
    }

    public String getIdx() {
        return idx;
    }

    public String getUri() {
        return uri;
    }
}