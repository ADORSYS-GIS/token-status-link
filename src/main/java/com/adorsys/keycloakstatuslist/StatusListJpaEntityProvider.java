package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.model.StatusListCounterEntity;
import com.adorsys.keycloakstatuslist.model.StatusListMappingEntity;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.jboss.logging.Logger;

import java.util.List;

public class StatusListJpaEntityProvider implements JpaEntityProvider {

    private static final Logger logger = Logger.getLogger(StatusListJpaEntityProvider.class);

    @Override
    public List<Class<?>> getEntities() {
        logger.debug("Registering entities: StatusListCounterEntity, StatusListMappingEntity");
        return List.of(
                StatusListCounterEntity.class,
                StatusListMappingEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/statuslist-changelog.xml";
    }

    @Override
    public void close() {
        logger.debug("Closing StatusListJpaEntityProvider");
    }

    @Override
    public String getFactoryId() {
        return StatusListJpaEntityProviderFactory.ID;
    }
}
