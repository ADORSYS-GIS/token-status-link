package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class CredentialRevocationResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public CredentialRevocationResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new CredentialRevocationResource(session);
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}