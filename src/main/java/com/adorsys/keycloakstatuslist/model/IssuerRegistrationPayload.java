package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.keycloak.jose.jwk.JWK;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssuerRegistrationPayload {

    // Static mapper for toString() to avoid creating it every time
    private static final ObjectMapper MAPPER =
            new ObjectMapper()
                    .registerModule(new JavaTimeModule())
                    .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("public_key")
    private JWK publicKey;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public JWK getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(JWK publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
