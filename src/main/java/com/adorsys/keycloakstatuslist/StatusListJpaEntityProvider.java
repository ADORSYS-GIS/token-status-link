package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.model.StatusListCounterEntity;
import com.adorsys.keycloakstatuslist.model.StatusListMappingEntity;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.Arrays;
import java.util.List;

public class StatusListJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        System.out.println("DEBUG: Registering entities: StatusListCounterEntity, StatusListMappingEntity");
        return Arrays.asList(
                StatusListCounterEntity.class,
                StatusListMappingEntity.class
        );
    }

    @Override
    public String getChangelogLocation() {
        System.out.println("DEBUG: No changelog location provided");
        return null; // No Liquibase changelog needed
    }

    public String getSchema() {
        System.out.println("DEBUG: Using schema: public");
        return null; // H2 doesn't require a schema; null uses default
    }

    @Override
    public void close() {
        System.out.println("DEBUG: Closing StatusListJpaEntityProvider");
    }

    @Override
    public String getFactoryId() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getFactoryId'");
    }
}