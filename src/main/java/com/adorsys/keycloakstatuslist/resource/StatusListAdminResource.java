package com.adorsys.keycloakstatuslist.resource;

import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialStatusPage;
import com.adorsys.keycloakstatuslist.model.CredentialStatusResponse;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.AdminAuth;

/**
 * Admin REST resource for querying credential status list mappings.
 * Requires realm admin authentication (realm-admin role on the realm-management client).
 */
public class StatusListAdminResource {

    private static final Logger logger = Logger.getLogger(StatusListAdminResource.class);
    static final int MAX_LIMIT = 100;

    private final KeycloakSession session;
    private final StatusListRepository repository;

    public StatusListAdminResource(KeycloakSession session) {
        this(session, new StatusListRepository(session));
    }

    StatusListAdminResource(KeycloakSession session, StatusListRepository repository) {
        this.session = session;
        this.repository = repository;
    }

    /**
     * Returns a paginated list of credential status entries for the current realm.
     *
     * @param offset zero-based pagination offset
     * @param limit maximum number of entries to return (capped at 100)
     * @return paginated response with credential status entries
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCredentials(
            @QueryParam("offset") @DefaultValue("0") int offset,
            @QueryParam("limit") @DefaultValue("20") int limit) {

        AdminAuth auth = authenticateAdmin();
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        RealmModel realm = session.getContext().getRealm();
        if (!hasRealmAdminRole(auth, realm)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        int effectiveOffset = Math.max(0, offset);
        int effectiveLimit = Math.min(Math.max(1, limit), MAX_LIMIT);
        String realmId = realm.getId();

        long total = repository.countMappings(realmId);
        List<StatusListMappingEntity> mappings = repository.getMappings(realmId, effectiveOffset, effectiveLimit);

        List<CredentialStatusResponse> items = mappings.stream()
                .map(m -> toResponse(m, realm))
                .toList();

        CredentialStatusPage page = new CredentialStatusPage(items, total, effectiveOffset, effectiveLimit);
        return Response.ok(page).build();
    }

    private CredentialStatusResponse toResponse(StatusListMappingEntity mapping, RealmModel realm) {
        String username = resolveUsername(mapping.getUserId(), realm);
        return new CredentialStatusResponse(
                mapping.getTokenId(),
                mapping.getUserId(),
                username,
                mapping.getStatus() != null ? mapping.getStatus().name() : null,
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
