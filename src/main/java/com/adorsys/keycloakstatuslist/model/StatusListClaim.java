package com.adorsys.keycloakstatuslist.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.util.Objects;
import org.keycloak.util.JsonSerialization;

/**
 * Represents the `status_list` claim object for a token, as defined in the <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token">IETF
 * OAuth Status List specification, Section 6.1</a>. This claim is included in OAuth 2.0 or OpenID
 * Connect tokens to reference a token's status in a status list resource. The claim consists of an
 * index (`idx`) and a URI (`uri`) that together allow verification of the token's validity status.
 * Jackson annotations are used to ensure proper JSON serialization of the fields into the required
 * structure: `{ "idx": <index>, "uri": <uri> }`.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class StatusListClaim {

    /**
     * The index of the token in the status list, as per Section 6.1 of the IETF OAuth Status List
     * specification. As an integer, it identifies the bit position in the status list where the
     * token's status is stored.
     */
    @JsonProperty("idx")
    private long idx;

    /**
     * The URI of the status list resource, as per Section 6.1 of the IETF OAuth Status List
     * specification. This URI points to the status list where the token's status is published and can
     * be retrieved. Annotated with `@JsonProperty("uri")` to map to the `uri` key in the JSON output.
     */
    @JsonProperty("uri")
    private String uri;

    /**
     * Default constructor for JSON deserialization. Required by Jackson to create an instance of this
     * class when deserializing from JSON.
     */
    public StatusListClaim() {
        // Default constructor for JSON deserialization
    }

    /**
     * Constructs a StatusListClaim with the specified index and URI.
     *
     * @param idx The index of the token in the status list.
     * @param uri The URI of the status list resource where the token's status is published.
     */
    public StatusListClaim(long idx, String uri) {
        this.idx = idx;
        this.uri = uri;
    }

    /**
     * Overloaded constructor — accepts index as int and URI object. Internally converts URI to
     * string.
     */
    public StatusListClaim(long idx, URI uri) {
        this(idx, uri.toString());
    }

    public long getIdx() {
        return idx;
    }

    public StatusListClaim setIdx(long idx) {
        this.idx = idx;
        return this;
    }

    public String getUri() {
        return uri;
    }

    public StatusListClaim setUri(String uri) {
        this.uri = uri;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        StatusListClaim that = (StatusListClaim) o;
        return idx == that.idx && Objects.equals(uri, that.uri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(idx, uri);
    }

    @Override
    public String toString() {
        return JsonSerialization.valueAsString(this);
    }
}
