package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialStatusFilter;
import com.adorsys.keycloakstatuslist.model.CredentialStatusPage;
import com.adorsys.keycloakstatuslist.model.CredentialStatusResponse;
import com.adorsys.keycloakstatuslist.model.CredentialStatusUpdateRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * Admin REST resource for querying and updating credential status list mappings.
 * Requires realm admin authentication (realm-admin role on the realm-management client).
 */
public class StatusListAdminResource {

    private static final Logger logger = Logger.getLogger(StatusListAdminResource.class);
    static final int MAX_LIMIT = 100;
    static final String NON_MATCHING_USER_ID = "__non_matching__";

    private final KeycloakSession session;
    private final StatusListRepository repository;
    private final StatusListService statusListService;

    public StatusListAdminResource(KeycloakSession session, StatusListService statusListService) {
        this(session, new StatusListRepository(session), statusListService);
    }

    StatusListAdminResource(
            KeycloakSession session, StatusListRepository repository, StatusListService statusListService) {
        this.session = session;
        this.repository = repository;
        this.statusListService = statusListService;
    }

    /**
     * Returns a paginated list of credential status entries for the current realm,
     * optionally filtered by username, token status, and metadata claims.
     *
     * @param offset   zero-based pagination offset
     * @param limit    maximum number of entries to return (capped at 100)
     * @param username filter by exact username (resolved to user ID)
     * @param status   filter by token status (VALID or INVALID)
     * @param claims   filter by metadata content (substring match, multiple values are ANDed)
     * @return paginated response with credential status entries
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCredentials(
            @QueryParam("offset") @DefaultValue("0") int offset,
            @QueryParam("limit") @DefaultValue("20") int limit,
            @QueryParam("username") String username,
            @QueryParam("status") String status,
            @QueryParam("claims") List<String> claims) {

        AdminAuth auth = authenticateAdmin();
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        RealmModel realm = session.getContext().getRealm();
        if (!hasRealmAdminRole(auth, realm)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        CredentialStatusFilter filter = buildFilter(realm, username, status, claims);
        if (filter == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"status must be VALID or INVALID\"}")
                    .build();
        }

        int effectiveOffset = Math.max(0, offset);
        int effectiveLimit = Math.min(Math.max(1, limit), MAX_LIMIT);
        String realmId = realm.getId();

        long total = repository.countMappings(realmId, filter);
        List<StatusListMappingEntity> mappings =
                repository.getMappings(realmId, filter, effectiveOffset, effectiveLimit);

        List<CredentialStatusResponse> items = mappings.stream()
                .map(m -> toResponse(m, realm))
                .toList();

        CredentialStatusPage page = new CredentialStatusPage(items, total, effectiveOffset, effectiveLimit);
        return Response.ok(page).build();
    }

    /**
     * Builds a filter from the query parameters. Returns null if the status value is invalid.
     */
    CredentialStatusFilter buildFilter(RealmModel realm, String username, String status, List<String> claims) {
        String userId = null;
        if (username != null && !username.isBlank()) {
            UserModel user = session.users().getUserByUsername(realm, username.trim());
            if (user == null) {
                userId = NON_MATCHING_USER_ID;
            } else {
                userId = user.getId();
            }
        }

        TokenStatus tokenStatus = null;
        if (status != null && !status.isBlank()) {
            try {
                tokenStatus = TokenStatus.valueOf(status.trim());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        List<String> effectiveClaims = claims != null
                ? claims.stream().filter(c -> c != null && !c.isBlank()).toList()
                : List.of();

        return new CredentialStatusFilter(userId, tokenStatus, effectiveClaims);
    }

    /**
     * Updates the token status of a credential on the status list server.
     *
     * @param id the primary key of the status list mapping entry
     * @param request the update request containing the new status (VALID or INVALID)
     * @return the updated credential status entry
     */
    @PUT
    @Path("/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateCredentialStatus(@PathParam("id") String id, CredentialStatusUpdateRequest request) {
        AdminAuth auth = authenticateAdmin();
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        RealmModel realm = session.getContext().getRealm();
        if (!hasRealmAdminRole(auth, realm)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        if (request == null || request.status() == null || request.status().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"status is required\"}")
                    .build();
        }

        TokenStatus newStatus;
        try {
            newStatus = TokenStatus.valueOf(request.status());
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"status must be VALID or INVALID\"}")
                    .build();
        }

        StatusListMappingEntity mapping = repository.findById(id);
        if (mapping == null || !realm.getId().equals(mapping.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\":\"credential not found\"}")
                    .build();
        }

        String requestId = UUID.randomUUID().toString();
        StatusListService.StatusListPayload payload = new StatusListService.StatusListPayload(
                mapping.getStatusListId(),
                List.of(new StatusListService.StatusListPayload.StatusEntry(mapping.getIdx(), newStatus.getValue())));

        try {
            statusListService.updateStatusList(payload, requestId);
        } catch (StatusListException e) {
            logger.errorf(
                    "Request ID: %s, Failed to update credential status for mapping %s: %s",
                    requestId, id, e.getMessage());
            return Response.status(Response.Status.BAD_GATEWAY)
                    .entity("{\"error\":\"failed to update status on status list server\"}")
                    .build();
        }

        mapping.setTokenStatus(newStatus);
        repository.updateMapping(mapping);

        logger.infof("Request ID: %s, Updated credential %s to status %s", requestId, id, newStatus.getValue());
        return Response.ok(toResponse(mapping, realm)).build();
    }

    private CredentialStatusResponse toResponse(StatusListMappingEntity mapping, RealmModel realm) {
        String username = resolveUsername(mapping.getUserId(), realm);
        return new CredentialStatusResponse(
                mapping.getId(),
                mapping.getTokenId(),
                mapping.getUserId(),
                username,
                mapping.getTokenStatus() != null ? mapping.getTokenStatus().name() : null,
                mapping.getStatusListId(),
                mapping.getIdx(),
                mapping.getCreatedTimestamp(),
                mapping.getMetadata());
    }

    private String resolveUsername(String userId, RealmModel realm) {
        if (userId == null) {
            return null;
        }
        UserModel user = session.users().getUserById(realm, userId);
        return user != null ? user.getUsername() : null;
    }

    AdminAuth authenticateAdmin() {
        AuthenticationManager.AuthResult authResult =
                new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null) {
            return null;
        }
        return new AdminAuth(
                session.getContext().getRealm(),
                authResult.getToken(),
                authResult.getUser(),
                authResult.getClient());
    }

    static boolean hasRealmAdminRole(AdminAuth auth, RealmModel realm) {
        String realmManagementClientId = realm.getClientByClientId("realm-management") != null
                ? "realm-management"
                : "master-realm";
        org.keycloak.models.ClientModel realmManagementClient = realm.getClientByClientId(realmManagementClientId);
        if (realmManagementClient == null) {
            logger.warnf("Could not find realm management client for realm: %s", realm.getName());
            return false;
        }
        return auth.hasAppRole(realmManagementClient, "realm-admin");
    }
}
