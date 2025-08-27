package com.adorsys.keycloakstatuslist.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;

@Entity
@Table(name = "status_list_counter")
public class StatusListCounterEntity {

    public static final String SEQUENCE_NAME = "status_list_counter_seq";
    public static final String SEQUENCE_GENERATOR_NAME = "status_list_counter_seq_gen";

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = SEQUENCE_GENERATOR_NAME)
    @SequenceGenerator(name = SEQUENCE_GENERATOR_NAME, sequenceName = SEQUENCE_NAME, allocationSize = 1)
    private Long id;

}
