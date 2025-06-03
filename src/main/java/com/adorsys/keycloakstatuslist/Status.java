package com.adorsys.keycloakstatuslist;

import java.util.Map;

public class Status {
    private StatusList statusList;

    public Status() {
    }

    public Status(StatusList statusList) {
        this.statusList = statusList;
    }

    public StatusList getStatusList() {
        return statusList;
    }

    public void setStatusList(StatusList statusList) {
        this.statusList = statusList;
    }

    public Map<String, Object> toMap() {
        return Map.of("status_list", statusList.toMap());
    }
}   