package com.adorsys.keycloakstatuslist.model;

import java.io.Serializable;
import java.util.Objects;

public class StatusListMappingId implements Serializable {
    private String statusListId;
    private long idx;

    public StatusListMappingId() {
    }

    public StatusListMappingId(String statusListId, long idx) {
        this.statusListId = statusListId;
        this.idx = idx;
    }

    public String getStatusListId() {
        return statusListId;
    }

    public void setStatusListId(String statusListId) {
        this.statusListId = statusListId;
    }

    public long getIdx() {
        return idx;
    }

    public void setIdx(long idx) {
        this.idx = idx;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof StatusListMappingId))
            return false;
        StatusListMappingId that = (StatusListMappingId) o;
        return idx == that.idx && Objects.equals(statusListId, that.statusListId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statusListId, idx);
    }
} 
