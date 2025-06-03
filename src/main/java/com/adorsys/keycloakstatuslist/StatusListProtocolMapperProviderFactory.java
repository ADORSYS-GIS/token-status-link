package com.adorsys.keycloakstatuslist;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class StatusListProtocolMapperProviderFactory implements ProtocolMapper {

    @Override
    public String getDisplayCategory() {
        return StatusListProtocolMapper.TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Status List Claim Mapper";
    }

    @Override
    public String getId() {
        return StatusListProtocolMapper.PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Factory for status list claim mapper";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return StatusListProtocolMapper.configProperties;
    }

    @Override
    public void close() {
        // No-op
    }

    @Override
    public ProtocolMapper create(KeycloakSession session) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'create'");
    }

    @Override
    public void init(Scope config) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'init'");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'postInit'");
    }

    @Override
    public String getProtocol() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getProtocol'");
    }
}