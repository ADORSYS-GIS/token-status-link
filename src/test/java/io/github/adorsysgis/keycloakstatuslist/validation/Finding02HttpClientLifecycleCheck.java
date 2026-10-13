package io.github.adorsysgis.keycloakstatuslist.validation;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import io.github.adorsysgis.keycloakstatuslist.StatusListProtocolMapper;
import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import io.github.adorsysgis.keycloakstatuslist.helpers.MockKeycloakTest;
import io.github.adorsysgis.keycloakstatuslist.service.CustomHttpClient;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Validation check for scan finding 2: {@code StatusListProtocolMapper} creates a new pooled {@link
 * CloseableHttpClient} on every construction (Keycloak constructs the mapper once per request) and
 * {@code Provider.close()} — which Keycloak invokes at the end of every session — is a no-op. The
 * clients are therefore never released.
 *
 * <p>Contract asserted here (fix-strategy agnostic): after constructing two mappers and closing
 * them, either at most one client was created (shared/cached per realm) or every client that was
 * created was closed. FAILS while per-request clients accumulate unclosed.
 */
class Finding02HttpClientLifecycleCheck extends MockKeycloakTest {

    @Test
    void httpClientsCreatedPerConstructionMustBeClosedOrShared() throws Exception {
        lenient().when(realm.getAttribute(StatusListConfig.STATUS_LIST_ENABLED)).thenReturn("true");
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("https://status.example.com");

        // Re-stub the static CustomHttpClient mock set up by MockKeycloakTest so every
        // creation returns a distinct client we can track individually.
        Field mockedField = MockKeycloakTest.class.getDeclaredField("mocked");
        mockedField.setAccessible(true);
        @SuppressWarnings("unchecked")
        MockedStatic<CustomHttpClient> customHttpClientStatic = (MockedStatic<CustomHttpClient>) mockedField.get(this);
        List<CloseableHttpClient> createdClients = new ArrayList<>();
        customHttpClientStatic
                .when(() -> CustomHttpClient.getHttpClient(any(StatusListConfig.class)))
                .thenAnswer(invocation -> {
                    CloseableHttpClient client = mock(CloseableHttpClient.class);
                    createdClients.add(client);
                    return client;
                });

        // Two constructions model two issuance requests; close() models KeycloakSession.close(),
        // which calls Provider.close() on every cached provider (DefaultKeycloakSession.close()).
        StatusListProtocolMapper firstRequest = new StatusListProtocolMapper(session);
        StatusListProtocolMapper secondRequest = new StatusListProtocolMapper(session);
        firstRequest.close();
        secondRequest.close();

        long closedClients = createdClients.stream()
                .filter(Finding02HttpClientLifecycleCheck::wasClosed)
                .count();
        assertTrue(
                createdClients.size() <= 1 || closedClients == createdClients.size(),
                () -> String.format(
                        "Created %d HTTP clients across 2 mapper constructions but closed only %d. "
                                + "Each per-request client must be closed from Provider.close() when the "
                                + "Keycloak session ends, or the client must be shared/cached per realm "
                                + "instead of created per request. See StatusListProtocolMapper.close() and "
                                + "CustomHttpClient.getHttpClient().",
                        createdClients.size(), closedClients));
    }

    private static boolean wasClosed(CloseableHttpClient client) {
        return Mockito.mockingDetails(client).getInvocations().stream()
                .anyMatch(invocation -> "close".equals(invocation.getMethod().getName()));
    }
}
