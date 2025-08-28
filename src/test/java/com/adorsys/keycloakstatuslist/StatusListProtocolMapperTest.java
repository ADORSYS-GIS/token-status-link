package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class StatusListProtocolMapperTest {

    LogCaptor logCaptor = LogCaptor.forClass(StatusListProtocolMapper.class);
    private StatusListProtocolMapper mapper;

    private KeycloakSession session;
    private KeycloakContext context;
    private RealmModel realm;
    private ClientModel client;

    private static final String TEST_SERVER_URL = "https://statuslist.eudi-adorsys.com/";
    private static final String TEST_CLIENT_ID = "test-client";

    @BeforeEach
    void setup() {
        session = mock(KeycloakSession.class);
        context = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        client = mock(ClientModel.class);

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(context.getClient()).thenReturn(client);
        when(client.getClientId()).thenReturn(TEST_CLIENT_ID);

        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(TEST_SERVER_URL);

        mapper = spy(new StatusListProtocolMapper(session));
    }

    @Test
    void testSetClaimsForSubjectWhenFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn("false");

        HashMap<String, Object> claims = new HashMap<>();
        mapper.setClaimsForSubject(claims, mock(UserSessionModel.class));

        assertTrue(claims.isEmpty(), "Claims should be empty if feature disabled");
        System.out.println(logCaptor.getDebugLogs());
    }

    @Test
    void testSetClaimsForSubjectWithInvalidUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("invalid-url");

        HashMap<String, Object> claims = new HashMap<>();
        mapper.setClaimsForSubject(claims, mock(UserSessionModel.class));

        assertTrue(claims.isEmpty(), "Claims should remain empty if server URL invalid");
        System.out.println(logCaptor.getDebugLogs());
    }
}
