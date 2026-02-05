package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class RevocationChallengeResourceFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "revocation-challenge";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RevocationChallengeResource create(KeycloakSession session) {
        return new RevocationChallengeResource(session);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No resources to clean up
    }
}
