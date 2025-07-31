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
        private RealmModel realm;

        private interface TestConstants {
                String TEST_REALM_ID = "test-realm";
                String TEST_CLIENT_ID = "test-client";
                String TEST_USER_ID = "user-123";
                long TEST_INDEX = 42L;
                long ERROR_INDEX = -1L;
                String TEST_CLAIM_NAME = "custom_status"; // Configured claim name for tests
                String TEST_SERVER_URL = "https://example.com/statuslist/";
                String TEST_LIST_ID = "99";
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
                        protected void storeIndexMapping(String statusListId, long idx, String userId, String tokenId,
                                        KeycloakSession session, Map<String, String> mapperConfig, com.adorsys.keycloakstatuslist.config.StatusListConfig realmConfig) {
                                // no-op
                        }
                });

                // Initialize mocks
                session = mock(KeycloakSession.class);
                mappingModel = mock(ProtocolMapperModel.class);
                userSession = mock(UserSessionModel.class);
                clientSessionCtx = mock(ClientSessionContext.class);
                realm = mock(RealmModel.class);

                // Configure common mocks
                configureMocks();

                // Set default configuration
                when(mappingModel.getConfig()).thenReturn(createDefaultConfig());
        }

        private void configureMocks() {
                // Mock KeycloakContext, RealmModel, and ClientModel
                KeycloakContext context = mock(KeycloakContext.class);
                when(session.getContext()).thenReturn(context);

                when(context.getRealm()).thenReturn(realm);
                when(realm.getId()).thenReturn(TestConstants.TEST_REALM_ID);
                
                // Mock realm attributes for StatusListConfig
                when(realm.getAttribute("status-list-enabled")).thenReturn("true");
                when(realm.getAttribute("status-list-server-url")).thenReturn(TestConstants.TEST_SERVER_URL);
                when(realm.getAttribute("status-list-auth-token")).thenReturn("test-token");
                when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
                when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
                when(realm.getAttribute("status-list-retry-count")).thenReturn("3");

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
                                StatusListProtocolMapper.Constants.LIST_ID_PROPERTY, TestConstants.TEST_LIST_ID,
                                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, TestConstants.TEST_CLAIM_NAME,
                                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true",
                                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true"));
        }

        @Test
        public void transformAccessToken_happyPath() {
                // Arrange
                AccessToken token = new AccessToken();
                String expectedUri = TestConstants.TEST_SERVER_URL + TestConstants.TEST_LIST_ID;

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertTrue(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Claim 'custom_status' should be present");

                @SuppressWarnings("unchecked")
                Map<String, Object> statusClaim = (Map<String, Object>) claims.get(TestConstants.TEST_CLAIM_NAME);
                assertNotNull(statusClaim, "Status claim map should not be null");

                @SuppressWarnings("unchecked")
                Map<String, Object> statusList = (Map<String, Object>) statusClaim.get("status_list");
                assertNotNull(statusList, "Nested 'status_list' map should not be null");

                assertEquals(expectedUri, statusList.get("uri"), "URI should match configured serverUrl/listId");
                assertEquals(String.valueOf(TestConstants.TEST_INDEX), statusList.get("idx"),
                                "Idx should match the stringified nextIndex");

                // Verify storeIndexMapping was called with correct parameters
                verify(mapper, times(1)).storeIndexMapping(
                        eq(TestConstants.TEST_LIST_ID), eq(TestConstants.TEST_INDEX), anyString(), isNull(), 
                        eq(session), anyMap(), any(com.adorsys.keycloakstatuslist.config.StatusListConfig.class)
                );
        }

        @Test
        public void transformIDToken_happyPath() {
                // Arrange
                IDToken token = new IDToken();

                // Act
                mapper.transformIDToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                assertTrue(token.getOtherClaims().containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Claim 'custom_status' should be present in ID token");
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
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present on error");
        }

        @Test
        public void defaultConfig_noClaimName() {
                // Arrange
                Map<String, String> configWithoutClaimName = new HashMap<>(Map.of(
                                StatusListProtocolMapper.Constants.LIST_ID_PROPERTY, TestConstants.TEST_LIST_ID,
                                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true",
                                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true"));
                when(mappingModel.getConfig()).thenReturn(configWithoutClaimName);
                AccessToken token = new AccessToken();

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertEquals(StatusListProtocolMapper.Constants.STATUS_ERROR_MESSAGE,
                                claims.get(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                                "Error claim should indicate missing claim name");
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present when claim name is missing");
        }

        @Test
        public void statusListDisabled_shouldNotProcess() {
                // Arrange
                when(realm.getAttribute("status-list-enabled")).thenReturn("false");
                AccessToken token = new AccessToken();

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present when status list is disabled");
                assertFalse(claims.containsKey(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                                "No error claim should be present when status list is disabled");
        }

        @Test
        public void invalidServerUrl_shouldAddErrorClaim() {
                // Arrange
                when(realm.getAttribute("status-list-server-url")).thenReturn("invalid-url");
                AccessToken token = new AccessToken();

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertEquals("Invalid status list server URL",
                                claims.get(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                                "Error claim should indicate invalid server URL");
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present when server URL is invalid");
        }

        @Test
        public void missingServerUrl_shouldAddErrorClaim() {
                // Arrange
                when(realm.getAttribute("status-list-server-url")).thenReturn("");
                AccessToken token = new AccessToken();

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertEquals("Status list server URL not configured",
                                claims.get(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                                "Error claim should indicate missing server URL");
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present when server URL is missing");
        }

        @Test
        public void nullServerUrl_shouldUseDefault() {
                // Arrange
                when(realm.getAttribute("status-list-server-url")).thenReturn(null);
                AccessToken token = new AccessToken();

                // Act
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                // Assert
                Map<String, Object> claims = token.getOtherClaims();
                assertTrue(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should be present when server URL is null (uses default)");
                assertFalse(claims.containsKey(StatusListProtocolMapper.Constants.STATUS_ERROR_CLAIM),
                                "No error claim should be present when server URL is null (uses default)");
        }
}
