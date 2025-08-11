package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.util.Map;

/**
 * Represents the `status_list` claim object for a token, as defined in the
 * <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">IETF
 * OAuth Status List specification, Section 6.1</a>.
 * This claim is included in OAuth 2.0 or OpenID Connect tokens to reference a
 * token's status in a status list resource.
 * The claim consists of an index (`idx`) and a URI (`uri`) that together allow
 * verification of the token's validity status.
 * Jackson annotations are used to ensure proper JSON serialization of the
 * fields into the required structure:
 * `{ "idx": <index>, "uri": <uri> }`.
 */
public class StatusListClaim {
    /**
     * The index of the token in the status list, as per Section 6.1 of the IETF
     * OAuth Status List specification.
     * This integer, represented as a string, identifies the bit position in the
     * status list where the token's status is stored.
     * Annotated with `@JsonProperty("idx")` to map to the `idx` key in the JSON
     * output.
     */
    @JsonProperty("idx")
    private final String idx;

    /**
     * The URI of the status list resource, as per Section 6.1 of the IETF OAuth
     * Status List specification.
     * This URI points to the status list where the token's status is published and
     * can be retrieved.
     * Annotated with `@JsonProperty("uri")` to map to the `uri` key in the JSON
     * output.
     */
    @JsonProperty("uri")
    private final String uri;

    /**
     * Constructs a StatusListClaim with the specified index and URI.
     *
     * @param idx The index of the token in the status list, as a string
     *            representation of an integer.
     * @param uri The URI of the status list resource where the token's status is
     *            published.
     */
    public StatusListClaim(int idx, String uri) {
        this.idx = String.valueOf(idx);
        this.uri = uri;
    }

    /**
     * Overloaded constructor — accepts index as int and URI object.
     * Internally converts URI to string.
     */
    public StatusListClaim(int idx, URI uri) {
        this(idx, uri.toString());
    }

    /**
     * Returns the index of the token in the status list.
     * Used by Jackson for serialization and by other components (e.g., Status
     * class) to access the index.
     *
     * @return The index as a string.
     */
    public String getIdx() {
        return idx;
    }

    /**
     * Returns the URI of the status list resource.
     * Used by Jackson for serialization and by other components (e.g., Status
     * class) to access the URI.
     *
     * @return The URI as a string.
     */
    public String getUri() {
        return uri;
    }

    public Map<String, Object> toMap() {
        return Map.of(
                "idx", idx,
                "uri", uri);
    }
}
