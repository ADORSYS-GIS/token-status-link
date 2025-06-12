package com.adorsys.keycloakstatuslist;

public class StatusList {
    private final String idx;
    private final String uri;

    public StatusList(String idx, String uri) {
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