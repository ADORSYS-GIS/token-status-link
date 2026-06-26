package com.adorsys.keycloakstatuslist.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.exception.StatusListException;
import com.adorsys.keycloakstatuslist.jpa.entity.StatusListMappingEntity;
import com.adorsys.keycloakstatuslist.jpa.repository.StatusListRepository;
import com.adorsys.keycloakstatuslist.model.CredentialStatusFilter;
import com.adorsys.keycloakstatuslist.model.CredentialStatusPage;
import com.adorsys.keycloakstatuslist.model.CredentialStatusResponse;
import com.adorsys.keycloakstatuslist.model.CredentialStatusUpdateRequest;
import com.adorsys.keycloakstatuslist.model.TokenStatus;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resources.admin.AdminAuth;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class StatusListAdminResourceTest {

    private static final String TEST_REALM_ID = "test-realm-id";
    private static final String TEST_USER_ID = "user-123";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_MAPPING_ID = "mapping-uuid-1";

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private StatusListRepository repository;

    @Mock
    private StatusListService statusListService;

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

        resource = spy(new StatusListAdminResource(session, repository, statusListService));
    }

    // --- GET tests ---

    @Test
    void shouldReturn401_WhenNotAuthenticated() {
        doReturn(null).when(resource).authenticateAdmin();

        Response response = resource.getCredentials(0, 20, null, null, null);

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    @Test
    void shouldReturn403_WhenNotRealmAdmin() {
        AdminAuth auth = mockAdminAuth(false);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.getCredentials(0, 20, null, null, null);

        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }

    @Test
    void shouldReturnEmptyPage_WhenNoMappingsExist() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();
        when(repository.countMappings(anyString(), any())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        Response response = resource.getCredentials(0, 20, null, null, null);

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
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 5L, "{\"vct\":\"IdentityCredential\"}");
        when(repository.countMappings(anyString(), any())).thenReturn(1L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20, null, null, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(1, page.total());
        assertEquals(1, page.items().size());

        CredentialStatusResponse item = page.items().get(0);
        assertEquals(TEST_MAPPING_ID, item.id());
        assertEquals("token-1", item.tokenId());
        assertEquals(TEST_USER_ID, item.userId());
        assertEquals(TEST_USERNAME, item.username());
        assertEquals("VALID", item.status());
        assertEquals("list-1", item.statusListId());
        assertEquals(5L, item.index());
        assertEquals("{\"vct\":\"IdentityCredential\"}", item.metadata());
    }

    @Test
    void shouldReturnNullUsername_WhenUserNotFound() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", "deleted-user-id", "list-1", 0L, null);
        when(repository.countMappings(anyString(), any())).thenReturn(1L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping));
        when(userProvider.getUserById(realm, "deleted-user-id")).thenReturn(null);

        Response response = resource.getCredentials(0, 20, null, null, null);

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

        StatusListMappingEntity mapping = createMapping(TEST_MAPPING_ID, "token-1", null, "list-1", 0L, null);
        when(repository.countMappings(anyString(), any())).thenReturn(1L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping));

        Response response = resource.getCredentials(0, 20, null, null, null);

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
        when(repository.countMappings(anyString(), any())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        Response response = resource.getCredentials(inputOffset, inputLimit, null, null, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(expectedOffset, page.offset());
        assertEquals(expectedLimit, page.limit());
    }

    @Test
    void shouldReturnMultipleMappings() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping1 = createMapping("id-1", "token-1", TEST_USER_ID, "list-1", 0L, null);
        StatusListMappingEntity mapping2 = createMapping("id-2", "token-2", TEST_USER_ID, "list-1", 1L, "{\"vct\":\"PID\"}");
        when(repository.countMappings(anyString(), any())).thenReturn(2L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping1, mapping2));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20, null, null, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(2, page.total());
        assertEquals(2, page.items().size());
    }

    @Test
    void shouldReturnNullMetadata_WhenNotSet() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping = createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 0L, null);
        when(repository.countMappings(anyString(), any())).thenReturn(1L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping));

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.getCredentials(0, 20, null, null, null);

        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertNull(page.items().get(0).metadata());
    }

    @Test
    void shouldReturn403_WhenRealmManagementClientNotFound() {
        AdminAuth auth = mockAdminAuth(false);
        doReturn(auth).when(resource).authenticateAdmin();
        when(realm.getClientByClientId("realm-management")).thenReturn(null);
        when(realm.getClientByClientId("master-realm")).thenReturn(null);

        Response response = resource.getCredentials(0, 20, null, null, null);

        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }

    // --- GET filter tests ---

    @Test
    void shouldFilterByUsername_WhenUserExists() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(TEST_USER_ID);
        when(userProvider.getUserByUsername(realm, TEST_USERNAME)).thenReturn(user);

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 0L, null);

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(1L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of(mapping));
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);
        when(user.getUsername()).thenReturn(TEST_USERNAME);

        Response response = resource.getCredentials(0, 20, TEST_USERNAME, null, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(TEST_USER_ID, filterCaptor.getValue().userId());
    }

    @Test
    void shouldReturnEmptyPage_WhenFilteredUsernameNotFound() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();
        when(userProvider.getUserByUsername(realm, "nonexistent")).thenReturn(null);

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        Response response = resource.getCredentials(0, 20, "nonexistent", null, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(StatusListAdminResource.NON_MATCHING_USER_ID, filterCaptor.getValue().userId());
        CredentialStatusPage page = (CredentialStatusPage) response.getEntity();
        assertEquals(0, page.total());
    }

    @ParameterizedTest
    @CsvSource({"VALID, VALID", "INVALID, INVALID"})
    void shouldFilterByStatus(String inputStatus, String expectedEnum) {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        Response response = resource.getCredentials(0, 20, null, inputStatus, null);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(TokenStatus.valueOf(expectedEnum), filterCaptor.getValue().tokenStatus());
    }

    @Test
    void shouldReturn400_WhenStatusFilterIsInvalid() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.getCredentials(0, 20, null, "SUSPENDED", null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    void shouldFilterByClaims() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        Response response = resource.getCredentials(0, 20, null, null, List.of("IdentityCredential"));

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(List.of("IdentityCredential"), filterCaptor.getValue().claims());
    }

    @Test
    void shouldFilterByMultipleClaims() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        List<String> claims = List.of("IdentityCredential", "alice@example.com");
        Response response = resource.getCredentials(0, 20, null, null, claims);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(claims, filterCaptor.getValue().claims());
    }

    @Test
    void shouldCombineAllFilters() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(TEST_USER_ID);
        when(userProvider.getUserByUsername(realm, TEST_USERNAME)).thenReturn(user);

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        List<String> claims = List.of("PID");
        Response response = resource.getCredentials(0, 20, TEST_USERNAME, "INVALID", claims);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        CredentialStatusFilter filter = filterCaptor.getValue();
        assertEquals(TEST_USER_ID, filter.userId());
        assertEquals(TokenStatus.INVALID, filter.tokenStatus());
        assertEquals(claims, filter.claims());
    }

    @Test
    void shouldIgnoreBlankClaimsEntries() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        ArgumentCaptor<CredentialStatusFilter> filterCaptor = ArgumentCaptor.forClass(CredentialStatusFilter.class);
        when(repository.countMappings(anyString(), filterCaptor.capture())).thenReturn(0L);
        when(repository.getMappings(anyString(), any(), anyInt(), anyInt())).thenReturn(List.of());

        List<String> claims = List.of("PID", "", "  ");
        Response response = resource.getCredentials(0, 20, null, null, claims);

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        assertEquals(List.of("PID"), filterCaptor.getValue().claims());
    }

    // --- PUT tests ---

    @Test
    void putShouldReturn401_WhenNotAuthenticated() {
        doReturn(null).when(resource).authenticateAdmin();

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.UNAUTHORIZED.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldReturn403_WhenNotRealmAdmin() {
        AdminAuth auth = mockAdminAuth(false);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldReturn400_WhenRequestIsNull() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, null);

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void putShouldReturn400_WhenStatusIsBlank(String status) {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest(status));

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldReturn400_WhenStatusIsUnknown() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        Response response =
                resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("SUSPENDED"));

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldReturn404_WhenMappingNotFound() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();
        when(repository.findById(TEST_MAPPING_ID)).thenReturn(null);

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldReturn404_WhenMappingBelongsToDifferentRealm() {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 5L, null);
        mapping.setRealmId("other-realm-id");
        when(repository.findById(TEST_MAPPING_ID)).thenReturn(mapping);

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatus());
    }

    @Test
    void putShouldRevokeCredentialSuccessfully() throws Exception {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 5L, "{\"vct\":\"PID\"}");
        when(repository.findById(TEST_MAPPING_ID)).thenReturn(mapping);

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).updateStatusList(payloadCaptor.capture(), anyString());

        StatusListService.StatusListPayload payload = payloadCaptor.getValue();
        assertEquals("list-1", payload.listId());
        assertEquals(1, payload.status().size());
        assertEquals(5L, payload.status().get(0).index());
        assertEquals("INVALID", payload.status().get(0).status());

        verify(repository).updateMapping(mapping);
        assertEquals(TokenStatus.INVALID, mapping.getTokenStatus());

        CredentialStatusResponse result = (CredentialStatusResponse) response.getEntity();
        assertEquals(TEST_MAPPING_ID, result.id());
        assertEquals("token-1", result.tokenId());
        assertEquals(TEST_USERNAME, result.username());
        assertEquals("INVALID", result.status());
    }

    @Test
    void putShouldRevalidateCredentialSuccessfully() throws Exception {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 3L, null);
        when(repository.findById(TEST_MAPPING_ID)).thenReturn(mapping);

        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(userProvider.getUserById(realm, TEST_USER_ID)).thenReturn(user);

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("VALID"));

        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());

        ArgumentCaptor<StatusListService.StatusListPayload> payloadCaptor =
                ArgumentCaptor.forClass(StatusListService.StatusListPayload.class);
        verify(statusListService).updateStatusList(payloadCaptor.capture(), anyString());

        assertEquals("VALID", payloadCaptor.getValue().status().get(0).status());

        verify(repository).updateMapping(mapping);
        assertEquals(TokenStatus.VALID, mapping.getTokenStatus());
    }

    @Test
    void putShouldReturn502_WhenStatusListServerFails() throws Exception {
        AdminAuth auth = mockAdminAuth(true);
        doReturn(auth).when(resource).authenticateAdmin();

        StatusListMappingEntity mapping =
                createMapping(TEST_MAPPING_ID, "token-1", TEST_USER_ID, "list-1", 5L, null);
        when(repository.findById(TEST_MAPPING_ID)).thenReturn(mapping);
        doThrow(new StatusListException("server unreachable"))
                .when(statusListService)
                .updateStatusList(any(), anyString());

        Response response = resource.updateCredentialStatus(TEST_MAPPING_ID, new CredentialStatusUpdateRequest("INVALID"));

        assertEquals(Response.Status.BAD_GATEWAY.getStatusCode(), response.getStatus());
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
            String id, String tokenId, String userId, String statusListId, long idx, String metadata) {
        StatusListMappingEntity mapping = new StatusListMappingEntity();
        mapping.setId(id);
        mapping.setTokenId(tokenId);
        mapping.setUserId(userId);
        mapping.setStatusListId(statusListId);
        mapping.setIdx(idx);
        mapping.setStatus(StatusListMappingEntity.MappingStatus.SUCCESS);
        mapping.setTokenStatus(TokenStatus.VALID);
        mapping.setMetadata(metadata);
        mapping.setRealmId(TEST_REALM_ID);
        return mapping;
    }
}
