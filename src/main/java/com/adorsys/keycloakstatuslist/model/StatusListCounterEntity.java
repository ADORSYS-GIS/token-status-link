package com.adorsys.keycloakstatuslist.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "status_list_counter")
public class StatusListCounterEntity {
    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "current_index")
    private long currentIndex;

    // Getters and setters
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