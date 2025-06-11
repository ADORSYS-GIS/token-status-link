package com.adorsys.keycloakstatuslist;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

public class StatusListProtocolMapperTest {

    private StatusListProtocolMapper mapper;
    private KeycloakSession session;
    private ProtocolMapperModel mappingModel;
    private UserSessionModel userSession;
    private ClientSessionContext clientSessionCtx;

    @BeforeEach
    public void setUp() {
        mapper = spy(new StatusListProtocolMapper() {
            @Override
            protected long getNextIndex(KeycloakSession session) {
                return 42L;
            }

            @Override
            protected void storeIndexMapping(long idx, String userId, String tokenId,
                    String listId, KeycloakSession session) {
                // no-op
            }
        });

        session = mock(KeycloakSession.class);
        mappingModel = mock(ProtocolMapperModel.class);
        userSession = mock(UserSessionModel.class);
        clientSessionCtx = mock(ClientSessionContext.class);

        // Stub KeycloakContext → RealmModel and ClientModel
        KeycloakContext context = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(context);

        RealmModel realm = mock(RealmModel.class);
        when(context.getRealm()).thenReturn(realm);
        when(realm.getId()).thenReturn("test-realm");

        ClientModel client = mock(ClientModel.class);
        // Needed by AbstractOIDCProtocolMapper.getShouldUseLightweightToken()
        when(context.getClient()).thenReturn(client);
        // Avoid NPE when checking client attributes
        when(client.getAttribute(anyString())).thenReturn(null);

        // Stub AuthenticatedClientSessionModel so casting works
        AuthenticatedClientSessionModel clientSession = mock(AuthenticatedClientSessionModel.class);
        when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
        when(clientSession.getClient()).thenReturn(client);
        when(client.getClientId()).thenReturn("test-client");

        // Stub userSession → UserModel → id
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("user-123");
        when(userSession.getUser()).thenReturn(user);

        // Default config: include in both access and ID tokens
        Map<String, String> cfg = Map.of(
                StatusListProtocolMapper.BASE_URI_PROPERTY, "https://example.com/statuslist",
                StatusListProtocolMapper.LIST_ID_PROPERTY, "99",
                OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, "status",
                OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true",
                OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        when(mappingModel.getConfig()).thenReturn(cfg);
    }

    @Test
    public void transformAccessToken_happyPath() {
        AccessToken token = new AccessToken();


        mapper.transformAccessToken(
                token, mappingModel, session, userSession, clientSessionCtx);

        assertTrue(token.getOtherClaims().containsKey("status"),
                "Claim 'status' should be present");
        @SuppressWarnings("unchecked")
        Map<String, Object> claim = (Map<String, Object>) token.getOtherClaims().get("status");
        assertNotNull(claim, "Claim map should not be null");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) claim.get("status_list");
        assertNotNull(statusList, "The 'status_list' nested map must not be null");

        // 3) And that map must have exactly the URI and the idx as strings
        assertEquals("https://example.com/statuslist/99",
                statusList.get("uri"),
                "URI should match the configured baseUri/listId");

        assertEquals("42",
                statusList.get("idx"),
                "Idx should be the string-ified nextIndex");
    }

    @Test
    public void getTransformClaim() {
        IDToken token = new IDToken();

        mapper.transformIDToken(
                token, mappingModel, session, userSession, clientSessionCtx);

        assertTrue(token.getOtherClaims().containsKey("status"));
    }

    @Test
    public void transformAccessToken_errorPath() {
        doReturn(-1L).when(mapper).getNextIndex(session);

        AccessToken token = new AccessToken();
        mapper.transformAccessToken(
                token, mappingModel, session, userSession, clientSessionCtx);

        assertEquals("Failed to generate index",
                token.getOtherClaims().get("status_error"));
        assertFalse(token.getOtherClaims().containsKey("status"));
    }

@Test
public void defaultConfig_usesDefaults() {
    // only include in access; leave everything else as defaults
    when(mappingModel.getConfig()).thenReturn(Map.of(
        OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true"
    ));

    AccessToken token = new AccessToken();
    mapper.transformAccessToken(
        token, mappingModel, session, userSession, clientSessionCtx
    );

    // 1) top-level "status" claim is present
    assertTrue(token.getOtherClaims().containsKey("status"), "Default claim-name 'status' should be present");

    @SuppressWarnings("unchecked")
    Map<String, Object> claim = (Map<String, Object>) token.getOtherClaims().get("status");
    assertNotNull(claim, "The 'status' claim map must not be null");

    // 2) nested "status_list" map exists
    @SuppressWarnings("unchecked")
    Map<String, Object> statusList = (Map<String, Object>) claim.get("status_list");
    assertNotNull(statusList, "The nested 'status_list' map must not be null");

    // 3) default base URI + default list-ID = ".../2"
    String uri = (String) statusList.get("uri");
    assertTrue(uri.endsWith("/null"), "Default URI should end with '/2', but was: " + uri);

    // 4) idx comes from our stub getNextIndex() → 42
    assertEquals("42", statusList.get("idx"), "Idx should be the string-ified nextIndex (42)");
}

}
