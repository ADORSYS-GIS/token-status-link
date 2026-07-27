package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request model for updating the status of a credential via the admin endpoint.
 */
public record CredentialStatusUpdateRequest(@JsonProperty("status") String status) {}
