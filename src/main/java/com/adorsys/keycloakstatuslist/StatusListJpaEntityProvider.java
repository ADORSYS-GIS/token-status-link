package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.model.StatusListMappingEntity;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.List;

public class StatusListJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        System.out.println("DEBUG: Registering entities: StatusListCounterEntity, StatusListMappingEntity");
        return List.of(
                StatusListMappingEntity.class
        );
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/statuslist-changelog.xml";
    }

    @Override
    public void close() {
        System.out.println("DEBUG: Closing StatusListJpaEntityProvider");
    }

    @Override
    public String getFactoryId() {
        return StatusListJpaEntityProviderFactory.ID;
    }
}