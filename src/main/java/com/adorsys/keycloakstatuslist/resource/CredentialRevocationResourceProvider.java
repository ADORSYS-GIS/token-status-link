package com.adorsys.keycloakstatuslist.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Resource provider for credential revocation endpoints.
 * This wrapper is required to register the REST resource with Keycloak.
 */
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
