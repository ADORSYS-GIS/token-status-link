package com.adorsys.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialStatusPage;
import com.adorsys.keycloakstatuslist.model.CredentialStatusResponse;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resources.admin.AdminAuth;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class StatusListAdminResourceTest {

    private static final String TEST_REALM_ID = "test-realm-id";
    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_USERNAME = "testuser";

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private StatusListRepository repository;

    @Mock
    private UserProvider userProvider;

    @Mock
    private ClientModel realmManagementClient;

    @Mock
    private RoleModel realmAdminRole;

    private StatusListAdminResource resource;

    @BeforeEach
    void setUp() {
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(realm.getId()).thenReturn(TEST_REALM_ID);
        lenient().when(session.users()).thenReturn(userProvider);

        resource = spy(new StatusListAdminResource(session, repository));
    }

    @Test
    void shouldReturn401_WhenNotAuthenticated() {
        doReturn(null).when(resource).authenticateAdmin();

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    @Test
    void shouldReturn403_WhenNotRealmAdmin() {
        AdminAuth auth = mockAdminAuth(false);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }

    @Test
    void shouldReturnEmptyPage_WhenNoMappingsExist() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(0L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of());

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(0, page.total());
        assertEquals(0, page.items().size());
        assertEquals(0, page.offset());
        assertEquals(20, page.limit());
    }

    @Test
    void shouldReturnMappingsWithUserDetails() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping("token-1", TEST_USER_ID, "list-1", 5L, "{\"vct\":\"IdentityCredential\"}");
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(1L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of(mapping));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(1, page.total());
        assertEquals(1, page.items().size());

        CredentialStatusResponse item = page.items().get(0);
        assertEquals("token-1", item.tokenId());
        assertEquals(TEST_USER_ID, item.userId());
        assertEquals(TEST_USERNAME, item.username());
        assertEquals("SUCCESS", item.status());
        assertEquals("list-1", item.statusListId());
        assertEquals(5L, item.index());
        assertEquals("{\"vct\":\"IdentityCredential\"}", item.metadata());
    }

    @Test
    void shouldReturnNullUsername_WhenUserNotFound() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping = createMapping("token-1", "deleted-user-id", "list-1", 0L, null);
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(1L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of(mapping));
        when(userProvider.getUserById(realm, "deleted-user-id")).thenReturn(null);

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        CredentialStatusResponse item = page.items().get(0);
        assertEquals("deleted-user-id", item.userId());
        assertNull(item.username());
    }

    @Test
    void shouldReturnNullUsername_WhenUserIdIsNull() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping = createMapping("token-1", null, "list-1", 0L, null);
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(1L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of(mapping));

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        CredentialStatusResponse item = page.items().get(0);
        assertNull(item.userId());
        assertNull(item.username());
    }

    @ParameterizedTest
    @CsvSource({"-5, 20, 0, 20", "0, 200, 0, 100", "0, 0, 0, 1", "10, 5, 10, 5"})
    void shouldClampPaginationParameters(int inputOffset, int inputLimit, int expectedOffset, int expectedLimit) {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(0L);
        when(repository.getMappings(TEST_REALM_ID, expectedOffset, expectedLimit)).thenReturn(List.of());

        Response response = resource.getCredentials(inputOffset, inputLimit);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(expectedOffset, page.offset());
        assertEquals(expectedLimit, page.limit());
    }

    @Test
    void shouldReturnMultipleMappings() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping1 = createMapping("token-1", TEST_USER_ID, "list-1", 0L, null);
        StatusListMappingEntity mapping2 = createMapping("token-2", TEST_USER_ID, "list-1", 1L, "{\"vct\":\"PID\"}");
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(2L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of(mapping1, mapping2));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(2, page.total());
        assertEquals(2, page.items().size());
    }

    @Test
    void shouldReturnNullMetadata_WhenNotSet() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping = createMapping("token-1", TEST_USER_ID, "list-1", 0L, null);
        when(repository.countMappings(TEST_REALM_ID)).thenReturn(1L);
        when(repository.getMappings(TEST_REALM_ID, 0, 20)).thenReturn(List.of(mapping));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20);

        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertNull(page.items().get(0).metadata());
    }

    @Test
    void shouldReturn403_WhenRealmManagementClientNotFound() {
        AdminAuth auth = mockAdminAuth(false);
        doReturn(auth).when(resource).authenticateAdmin();
        when(realm.getClientByClientId("realm-management")).thenReturn(null);
        when(realm.getClientByClientId("master-realm")).thenReturn(null);

        Response response = resource.getCredentials(0, 20);

        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }

    // --- Helper methods ---

    private AdminAuth mockAdminAuth(boolean isRealmAdmin) {
        UserModel adminUser = mock(UserModel.class);
        ClientModel adminClient = mock(ClientModel.class);

        lenient().when(realm.getClientByClientId("realm-management")).thenReturn(realmManagementClient);
        lenient().when(realmManagementClient.getRole("realm-admin")).thenReturn(realmAdminRole);

        if (isRealmAdmin) {
            lenient().when(adminUser.hasRole(realmAdminRole)).thenReturn(true);
            lenient().when(adminClient.hasScope(realmAdminRole)).thenReturn(true);
        }

        return new AdminAuth(realm, new AccessToken(), adminUser, adminClient);
    }

    private StatusListMappingEntity createMapping(
            String tokenId, String userId, String statusListId, long idx, String metadata) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setTokenId(tokenId);
        mapping.setUserId(userId);
        mapping.setStatusListId(statusListId);
        mapping.setIdx(idx);
        mapping.setStatus(StatusListMappingEntity.MappingStatus.SUCCESS);
        mapping.setMetadata(metadata);
        mapping.setRealmId(TEST_REALM_ID);
        return mapping;
    }
}
