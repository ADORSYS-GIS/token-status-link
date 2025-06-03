package com.adorsys.keycloakstatuslist;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

public class StatusListProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "status-list-protocol-mapper";
    public static final String BASE_URI_PROPERTY = "status.list.base_uri";
    public static final String LIST_ID_PROPERTY = "status.list.list_id";
    static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        // Configuration property for the base URI
        ProviderConfigProperty baseUriProperty = new ProviderConfigProperty();
        baseUriProperty.setName(BASE_URI_PROPERTY);
        baseUriProperty.setLabel("Status List Base URI");
        baseUriProperty.setType(ProviderConfigProperty.STRING_TYPE);
        baseUriProperty.setHelpText("The base URI for the status list (e.g., https://example.com/statuslists)");
        baseUriProperty.setDefaultValue("https://example.com/statuslists");
        configProperties.add(baseUriProperty);

        // Configuration property for the list ID
        ProviderConfigProperty listIdProperty = new ProviderConfigProperty();
        listIdProperty.setName(LIST_ID_PROPERTY);
        listIdProperty.setLabel("Status List ID");
        listIdProperty.setType(ProviderConfigProperty.STRING_TYPE);
        listIdProperty.setHelpText("The list ID to append to the base URI (e.g., 1)");
        listIdProperty.setDefaultValue("1");
        configProperties.add(listIdProperty);

        // Standard token claim name and token inclusion properties
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, StatusListProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Status List Claim Mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds a status list claim with a counter-based idx and configurable URI to the token";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        // Get the configured base URI and list ID from the mapper configuration
        String baseUri = mappingModel.getConfig().getOrDefault(BASE_URI_PROPERTY, "https://example.com/statuslists");
        String listId = mappingModel.getConfig().getOrDefault(LIST_ID_PROPERTY, "1");

        // Construct the URI using String.format (equivalent to Rust format!("{}/{}", uri, list_id))
        String uri = String.format("%s/%s", baseUri, listId);

        // Get the StatusListIndexStorageProvider
        StatusListIndexStorageProvider storageProvider = keycloakSession.getProvider(StatusListIndexStorageProvider.class);

        // Get the next index
        long idx = storageProvider.getNextIndex(keycloakSession);

        // Store the index mapping and send to statuslist-server.com
        String userId = userSession != null ? userSession.getUser().getId() : null;
        storageProvider.storeIndexMapping(idx, userId, token.getId(), listId, keycloakSession);

        // Create the status list claim
        StatusList statusList = new StatusList(String.valueOf(idx), uri);
        Status status = new Status(statusList);

        // Add the claim to the token
        String claimName = mappingModel.getConfig().getOrDefault(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "status");
        token.getOtherClaims().put(claimName, status.toMap());
    }
}