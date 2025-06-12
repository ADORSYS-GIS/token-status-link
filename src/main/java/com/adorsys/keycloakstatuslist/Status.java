package com.adorsys.keycloakstatuslist;

import java.util.Map;

public class Status {
    private final StatusList statusList;

    public Status(StatusList statusList) {
        this.statusList = statusList;
    }

    public Map<String, Object> toMap() {
        return Map.of("status_list", Map.of("idx", statusList.getIdx(), "uri", statusList.getUri()));
    }
}