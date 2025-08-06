package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class StatusListProtocolMapperTest {

        private StatusListProtocolMapper mapper;
        private KeycloakSession session;
        private ProtocolMapperModel mappingModel;
        private UserSessionModel userSession;
        private ClientSessionContext clientSessionCtx;
        private RealmModel realm;

        // Mocked StatusListConfig to control serverUrl in tests
        private StatusListConfig statusListConfig;

        private interface TestConstants {
                String TEST_REALM_ID = "test-realm";
                String TEST_CLIENT_ID = "test-client";
                String TEST_USER_ID = "user-123";
                long TEST_INDEX = 42L;
                long ERROR_INDEX = -1L;
                String TEST_CLAIM_NAME = "custom_status";
                String TEST_SERVER_URL = "https://example.statuslist.com";
                String TEST_LIST_ID = "99";
        }

        @BeforeEach
        public void setUp() {
                statusListConfig = mock(StatusListConfig.class);

                mapper = spy(new StatusListProtocolMapper() {
                        @Override
                        protected long getNextIndex(KeycloakSession session) {
                                return TestConstants.TEST_INDEX;
                        }

                        @Override
                        protected void storeIndexMapping(String statusListId, long idx, String userId, String tokenId,
                                        KeycloakSession session, Map<String, String> mapperConfig,
                                        StatusListConfig realmConfig) {
                                // no-op
                        }

                        // Override to return mocked statusListConfig so we can control it in tests
                        @Override
                        public StatusListConfig getStatusListConfig(RealmModel realm) {
                                return statusListConfig;
                        }
                });

                session = mock(KeycloakSession.class);
                mappingModel = mock(ProtocolMapperModel.class);
                userSession = mock(UserSessionModel.class);
                clientSessionCtx = mock(ClientSessionContext.class);
                realm = mock(RealmModel.class);

                configureMocks();

                when(mappingModel.getConfig()).thenReturn(createDefaultConfig());

                // Default for most tests: config enabled and valid URL
                when(statusListConfig.isEnabled()).thenReturn(true);
                when(statusListConfig.getServerUrl()).thenReturn(TestConstants.TEST_SERVER_URL);
        }

        private void configureMocks() {
                KeycloakContext context = mock(KeycloakContext.class);
                when(session.getContext()).thenReturn(context);
                when(context.getRealm()).thenReturn(realm);
                when(realm.getId()).thenReturn(TestConstants.TEST_REALM_ID);

                when(realm.getAttribute("status-list-enabled")).thenReturn("true");
                when(realm.getAttribute("status-list-server-url")).thenReturn(TestConstants.TEST_SERVER_URL);
                when(realm.getAttribute("status-list-auth-token")).thenReturn("test-token");
                when(realm.getAttribute("status-list-connect-timeout")).thenReturn("5000");
                when(realm.getAttribute("status-list-read-timeout")).thenReturn("5000");
                when(realm.getAttribute("status-list-retry-count")).thenReturn("3");

                ClientModel client = mock(ClientModel.class);
                when(context.getClient()).thenReturn(client);
                when(client.getAttribute(anyString())).thenReturn(null);

                AuthenticatedClientSessionModel clientSession = mock(AuthenticatedClientSessionModel.class);
                when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
                when(clientSession.getClient()).thenReturn(client);
                when(client.getClientId()).thenReturn(TestConstants.TEST_CLIENT_ID);

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
                AccessToken token = new AccessToken();
                String expectedUri = TestConstants.TEST_SERVER_URL + "/status-lists/" + TestConstants.TEST_LIST_ID;

                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertTrue(claims.containsKey(TestConstants.TEST_CLAIM_NAME), "Status claim should be present");

                @SuppressWarnings("unchecked")
                Map<String, Object> statusClaim = (Map<String, Object>) claims.get(TestConstants.TEST_CLAIM_NAME);
                assertNotNull(statusClaim);

                @SuppressWarnings("unchecked")
                Map<String, Object> statusList = (Map<String, Object>) statusClaim.get("status_list");
                assertNotNull(statusList);

                assertEquals(expectedUri, statusList.get("uri"));
                assertEquals(String.valueOf(TestConstants.TEST_INDEX), statusList.get("idx"));

                verify(mapper, times(1)).storeIndexMapping(
                                eq(TestConstants.TEST_LIST_ID), eq(TestConstants.TEST_INDEX), anyString(), isNull(),
                                eq(session), anyMap(),
                                any(StatusListConfig.class));
        }

        @Test
        public void transformIDToken_happyPath() {
                IDToken token = new IDToken();
                mapper.transformIDToken(token, mappingModel, session, userSession, clientSessionCtx);
                assertTrue(token.getOtherClaims().containsKey(TestConstants.TEST_CLAIM_NAME));
        }

        @Test
        public void transformAccessToken_errorPath_indexFails() {
                doReturn(TestConstants.ERROR_INDEX).when(mapper).getNextIndex(session);
                AccessToken token = new AccessToken();

                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present on index error");
        }

        @Test
        public void defaultConfig_noClaimName() {
                Map<String, String> configWithoutClaimName = new HashMap<>(Map.of(
                                StatusListProtocolMapper.Constants.LIST_ID_PROPERTY, TestConstants.TEST_LIST_ID,
                                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true",
                                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true"));
                when(mappingModel.getConfig()).thenReturn(configWithoutClaimName);

                AccessToken token = new AccessToken();
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME),
                                "Status claim should not be present when claim name is missing");
        }

        @Test
        public void statusListDisabled_shouldNotProcess() {
                when(statusListConfig.isEnabled()).thenReturn(false);

                AccessToken token = new AccessToken();
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME));
        }

        @Test
        public void invalidServerUrl_shouldNotAddClaim() {
                when(statusListConfig.getServerUrl()).thenReturn("invalid-url");

                AccessToken token = new AccessToken();
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME));
        }

        @Test
        public void missingServerUrl_shouldNotAddClaim() {
                when(statusListConfig.getServerUrl()).thenReturn("");

                AccessToken token = new AccessToken();
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME));
        }

        @Test
        public void nullServerUrl_shouldNotAddClaim() {
                when(statusListConfig.getServerUrl()).thenReturn(null);

                AccessToken token = new AccessToken();
                mapper.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);

                Map<String, Object> claims = token.getOtherClaims();
                assertFalse(claims.containsKey(TestConstants.TEST_CLAIM_NAME));
        }
}
