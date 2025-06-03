package com.adorsys.keycloakstatuslist;

import java.util.Map;

public class StatusList {
    private String idx;
    private String uri;

    public StatusList() {
    }

    public StatusList(String idx, String uri) {
        this.idx = idx;
        this.uri = uri;
    }

    public String getIdx() {
        return idx;
    }

    public void setIdx(String idx) {
        this.idx = idx;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public Map<String, Object> toMap() {
        return Map.of(
            "idx", idx,
            "uri", uri
        );
    }
}