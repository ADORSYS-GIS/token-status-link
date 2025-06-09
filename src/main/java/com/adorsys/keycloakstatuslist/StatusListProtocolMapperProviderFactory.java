package com.adorsys.keycloakstatuslist;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class StatusListProtocolMapperProviderFactory extends AbstractOIDCProtocolMapper{

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

    // Removed the 'create' method as it cannot override the final method from AbstractOIDCProtocolMapper

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getProtocol() {
        return "status list client";
   
    }
}