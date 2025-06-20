package com.adorsys.keycloakstatuslist.model;

import jakarta.persistence.*;

@Entity
@Table(name = "STATUS_LIST_COUNTER")
public class StatusListCounterEntity {

    @Id
    @Column(name = "id", nullable = false)
    private String id;

    @Column(name = "current_index", nullable = false)
    private long currentIndex;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public long getCurrentIndex() {
        return currentIndex;
    }

    public void setCurrentIndex(long currentIndex) {
        this.currentIndex = currentIndex;
    }
}