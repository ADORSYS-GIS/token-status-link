package com.adorsys.keycloakstatuslist;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import com.adorsys.keycloakstatuslist.helpers.MockKeycloakTest;
import com.adorsys.keycloakstatuslist.model.Status;
import com.adorsys.keycloakstatuslist.model.StatusListClaim;
import com.adorsys.keycloakstatuslist.service.StatusListService;
import jakarta.persistence.PersistenceException;
import jakarta.persistence.Query;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.UriBuilder;
import nl.altindag.log.LogCaptor;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.mockito.Mock;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Random;

import static com.adorsys.keycloakstatuslist.StatusListProtocolMapper.Constants;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class StatusListProtocolMapperTest extends MockKeycloakTest {

    LogCaptor logCaptor = LogCaptor.forClass(StatusListProtocolMapper.class);

    protected static final String TEST_SERVER_URL = "https://example.com";

    @Mock
    ProtocolMapperModel mapperModel;

    StatusListProtocolMapper mapper;
    HashMap<String, Object> claims;

    @BeforeEach
    void setup() {
        // Initialize mapper and its model
        mapper = spy(new StatusListProtocolMapper(session));
        setPrivateField(mapper, "mapperModel", mapperModel);

        // Initialize claims (credential payload)
        claims = new HashMap<>();
        claims.put(Constants.ID_CLAIM_KEY, "did:example:123456789");

        // Run mocks
        mockDefaultRealmConfig();

        StatusListService mockStatusListService = new StatusListService(TEST_SERVER_URL, null, httpClient);
        lenient().doReturn(mockStatusListService).when(mapper).getStatusListService(any(StatusListConfig.class));
    }

    @Test
    void testDefaultConstructor() {
        // An empty mapper constructor is required by Keycloak
        new StatusListProtocolMapper();
    }

    @Test
    void shouldSendStatusesThenMapSuccessfully_CreateListIfNotExists() {
        long idx = mockGetNextIndex();
        mockHttpClientExecute((req) -> {
            switch (req.getMethod()) {
                // Check if status list already exists
                case HttpMethod.GET -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_NOT_FOUND);
                // Create new status list
                case HttpMethod.POST -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_CREATED);
                default -> fail("Unexpected HTTP call: " + req.getMethod());
            }
        });

        mapper.setClaimsForSubject(claims, userSession);
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));
        assertInstanceOf(Status.class, claims.get(Constants.STATUS_CLAIM_KEY));

        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, listUri(TEST_REALM_ID))));
    }

    @Test
    void shouldSendStatusesThenMapSuccessfully_UpdateListIfExists() {
        long idx = mockGetNextIndex();
        mockHttpClientExecute((req) -> {
            switch (req.getMethod()) {
                // Check if status list already exists
                case HttpMethod.GET -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_OK);
                // Create new status list
                case HttpMethod.PATCH -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_OK);
                default -> fail("Unexpected HTTP call: " + req.getMethod());
            }
        });

        mapper.setClaimsForSubject(claims, userSession);
        assertThat(claims.keySet(), hasItem(Constants.STATUS_CLAIM_KEY));

        Status status = (Status) claims.get(Constants.STATUS_CLAIM_KEY);
        assertThat(status.getStatusList(), equalTo(new StatusListClaim(idx, listUri(TEST_REALM_ID))));
    }

    @Test
    void shouldNotMap_IfFeatureDisabled() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED))
                .thenReturn("false");

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getDebugLogs(), hasItem(containsString("Status list is disabled")));
    }

    @Test
    void shouldNotMap_IfInvalidStatusServerUrl() {
        when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("invalid-url");

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Invalid status list server URL")));
    }

    @Test
    void shouldNotMap_IfCantGetNextIndex() {
        mockFailingGetNextIndex();

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItem(containsString("Failed to get next index")));
    }

    @Test
    void shouldNotMap_IfCantCheckStatusListExists() {
        mockGetNextIndex();
        mockHttpClientExecute((req) -> {
            // Check if status list already exists
            if (req.getMethod().equals(HttpMethod.GET)) {
                when(httpResponse.getCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
            } else {
                fail("Unexpected HTTP call: " + req.getMethod());
            }
        });

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItems(
                containsString("Failed to store index mapping"),
                containsString("Failed to send status to server. Status claim not mapped")
        ));
        assertThat(logCaptor.getErrorLogs(), not(hasItem(
                containsString("Error publishing or updating status list on server")
        )));
    }

    @Test
    void shouldNotMap_IfCantPublishStatus() {
        mockGetNextIndex();
        mockHttpClientExecute((req) -> {
            switch (req.getMethod()) {
                // Check if status list already exists
                case HttpMethod.GET -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_NOT_FOUND);
                // Create new status list
                case HttpMethod.POST -> when(httpResponse.getCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
                default -> fail("Unexpected HTTP call: " + req.getMethod());
            }
        });

        mapper.setClaimsForSubject(claims, userSession);

        assertThat("Claims should remain unmapped", claims.keySet(), not(hasItem(Constants.STATUS_CLAIM_KEY)));
        assertThat(logCaptor.getErrorLogs(), hasItems(
                containsString("Failed to store index mapping"),
                containsString("Failed to send status to server. Status claim not mapped")
        ));
        assertThat(logCaptor.getErrorLogs(), not(hasItem(
                containsString("Error publishing or updating status list on server")
        )));
    }

    private void mockDefaultRealmConfig() {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL)).thenReturn(TEST_SERVER_URL);
    }

    private long mockGetNextIndex() {
        long nextIndex = new Random().nextLong();
        Query query = mock(Query.class);
        when(entityManager.createNativeQuery(startsWith("SELECT nextval"))).thenReturn(query);
        when(query.getSingleResult()).thenAnswer(invocation -> nextIndex);
        return nextIndex;
    }

    private void mockFailingGetNextIndex() {
        Query query = mock(Query.class);
        when(entityManager.createNativeQuery(startsWith("SELECT nextval"))).thenReturn(query);
        when(query.getSingleResult()).thenThrow(new PersistenceException());
    }

    @FunctionalInterface
    private interface HttpClientExecuteHandler {
        void run(ClassicHttpRequest request) throws Exception;
    }

    private void mockHttpClientExecute(HttpClientExecuteHandler executeHandler) {
        try {
            when(httpClient.execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class)))
                    .thenAnswer(invocation -> {
                        ClassicHttpRequest request = invocation.getArgument(0);
                        HttpClientResponseHandler<?> handler = invocation.getArgument(1);
                        executeHandler.run(request);
                        return handler.handleResponse(httpResponse);
                    });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("SameParameterValue")
    private URI listUri(String listId) {
        return UriBuilder.fromUri(TEST_SERVER_URL)
                .path(String.format(Constants.HTTP_ENDPOINT_RETRIEVE_PATH, listId))
                .build();
    }
}
