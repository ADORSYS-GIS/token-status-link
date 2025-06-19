package com.adorsys.keycloakstatuslist.model;

import java.util.Map;

public class Status {
    private final StatusListClaim statusList;

    public Status(StatusListClaim statusList) {
        this.statusList = statusList;
    }

    public Map<String, Object> toMap() {
        return Map.of("status_list", Map.of("idx", statusList.getIdx(), "uri", statusList.getUri()));
    }
}