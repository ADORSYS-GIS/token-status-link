package com.adorsys.keycloakstatuslist;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class StatusListProtocolMapperTest {

    private StatusListProtocolMapper mapper;
    private KeycloakSession session;
    private ProtocolMapperModel mappingModel;
    private UserSessionModel userSession;
    private ClientSessionContext clientSessionCtx;

    private interface TestConstants {
        String TEST_REALM_ID = "test-realm";
        String TEST_CLIENT_ID = "test-client";
        String TEST_USER_ID = "user-123";
        long TEST_INDEX = 42L;
        long ERROR_INDEX = -1L;
    }

    @BeforeEach
    public void setUp() {
        // Spy on the mapper with stubbed methods
        mapper = spy(new StatusListProtocolMapper() {
            @Override
            protected long getNextIndex(KeycloakSession session) {
                return TestConstants.TEST_INDEX;
            }

            @Override
            protected void storeIndexMapping(long idx, String userId, String tokenId,
                    String listId, KeycloakSession session, Map<String, String> config) {
                // no-op
            }
        });

        // Initialize mocks
        session = mock(KeycloakSession.class);
        mappingModel = mock(ProtocolMapperModel.class);
        userSession = mock(UserSessionModel.class);
        clientSessionCtx = mock(ClientSessionContext.class);

        // Configure common mocks
        configureMocks();

        // Set default configuration
        when(mappingModel.getConfig()).thenReturn(createDefaultConfig());
    }

    private void configureMocks() {
        // Mock KeycloakContext, RealmModel, and ClientModel
        KeycloakContext context = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(context);

        RealmModel realm = mock(RealmModel.class);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getId()).thenReturn(TestConstants.TEST_REALM_ID);

        ClientModel client = mock(ClientModel.class);
        when(context.getClient()).thenReturn(client);
        when(client.getAttribute(anyString())).thenReturn(null);

        // Mock ClientSession
        AuthenticatedClientSessionModel clientSession = mock(AuthenticatedClientSessionModel.class);
        when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
        when(clientSession.getClient()).thenReturn(client);
        when(client.getClientId()).thenReturn(TestConstants.TEST_CLIENT_ID);

        // Mock UserSession and UserModel
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(TestConstants.TEST_USER_ID);
        when(userSession.getUser()).thenReturn(user);
    }

    private Map<String, String> createDefaultConfig() {
        return new HashMap<>(Map.of(
                StatusListProtocolMapper.Constants.BASE_URI_PROPERTY, "https://example.com/statuslist",
                StatusListProtocolMapper.Constants.LIST_ID_PROPERTY, "99",
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME,
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true",
                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true"));
    }

    @Test
    public void transformAccessToken_happyPath() {
        // Arrange
        AccessToken token = new AccessToken();
        String expectedUri = "https://example.com/statuslist/99";

        // Act
        mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

        // Assert
        Map<String, Object> claims = token.getOtherClaims();
        assertTrue(claims.containsKey(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME),
                "Claim 'status' should be present");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusClaim = (Map<String, Object>) claims
                .get(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME);
        assertNotNull(statusClaim, "Status claim map should not be null");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) statusClaim.get("status_list");
        assertNotNull(statusList, "Nested 'status_list' map should not be null");

        assertEquals(expectedUri, statusList.get("uri"), "URI should match configured baseUri/listId");
        assertEquals(String.valueOf(TestConstants.TEST_INDEX), statusList.get("idx"),
                "Idx should match the stringified nextIndex");
    }

    @Test
    public void transformIDToken_happyPath() {
        // Arrange
        IDToken token = new IDToken();

        // Act
        mapper.transformIDToken(token, mappingModel, session, userSession, clientSessionCtx);

        // Assert
        assertTrue(token.getOtherClaims().containsKey(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME),
                "Claim 'status' should be present in ID token");
    }

    @Test
    public void transformAccessToken_errorPath() {
        // Arrange
        doReturn(TestConstants.ERROR_INDEX).when(mapper).getNextIndex(session);
        AccessToken token = new AccessToken();

        // Act
        mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

        // Assert
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals(StatusListProtocolMapper.Constants.STATUS_ERROR_MESSAGE,
                claims.get(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                "Error claim should indicate index generation failure");
        assertFalse(claims.containsKey(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME),
                "Status claim should not be present on error");
    }

    @Test
    public void defaultConfig_usesDefaults() {
        // Arrange
        Map<String, String> minimalConfig = new HashMap<>(Map.of(
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true"));
        when(mappingModel.getConfig()).thenReturn(minimalConfig);
        AccessToken token = new AccessToken();

        // Act
        mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

        // Assert
        Map<String, Object> claims = token.getOtherClaims();
        assertTrue(claims.containsKey(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME),
                "Default claim 'status' should be present");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusClaim = (Map<String, Object>) claims
                .get(StatusListProtocolMapper.Constants.DEFAULT_TOKEN_CLAIM_NAME);
        assertNotNull(statusClaim, "Status claim map should not be null");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) statusClaim.get("status_list");
        assertNotNull(statusList, "Nested 'status_list' map should not be null");

        String uri = (String) statusList.get("uri");
        assertTrue(
                uri.endsWith(
                        "https://statuslist.eudi-adorsys.com/" + StatusListProtocolMapper.Constants.DEFAULT_LIST_ID),
                "URI should end with default list ID, but was: " + uri);

        assertEquals(String.valueOf(TestConstants.TEST_INDEX), statusList.get("idx"),
                "Idx should match the stringified nextIndex");
    }
}