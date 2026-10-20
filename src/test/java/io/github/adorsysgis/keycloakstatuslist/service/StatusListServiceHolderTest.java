package io.github.adorsysgis.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloakstatuslist.config.StatusListConfig;
import java.util.HashMap;
import java.util.Map;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests for {@link StatusListServiceHolder}. */
@ExtendWith(MockitoExtension.class)
class StatusListServiceHolderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    /** Backs the mocked session's attributes so setAttribute feeds getAttribute. */
    private final Map<String, Object> attributes = new HashMap<>();

    private void stubSessionAttributes() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        // StatusListConfig reads several realm attributes; keep them lenient.
        lenient()
                .when(realm.getAttribute(StatusListConfig.STATUS_LIST_SERVER_URL))
                .thenReturn("https://example.com");
        when(session.getAttribute(anyString(), any(Class.class))).thenAnswer(invocation -> {
            String name = invocation.getArgument(0);
            Class<?> type = invocation.getArgument(1);
            Object value = attributes.get(name);
            return value != null && type.isInstance(value) ? value : null;
        });
        doAnswer(invocation -> {
                    attributes.put(invocation.getArgument(0), invocation.getArgument(1));
                    return null;
                })
                .when(session)
                .setAttribute(anyString(), any());
    }

    @Test
    void getOrCreateBuildsOnceAndSharesPerSession() {
        stubSessionAttributes();
        try (MockedStatic<CustomHttpClient> httpClientStatic = mockStatic(CustomHttpClient.class);
                MockedStatic<CircuitBreaker> circuitBreakerStatic = mockStatic(CircuitBreaker.class);
                MockedConstruction<CryptoIdentityService> cryptoServiceConstruction =
                        mockConstruction(CryptoIdentityService.class, (mock, ctx) -> when(mock.getJwtToken(any()))
                                .thenReturn("token"));
                MockedConstruction<StatusListService> serviceConstruction = mockConstruction(StatusListService.class)) {

            httpClientStatic
                    .when(() -> CustomHttpClient.getHttpClient(any(StatusListConfig.class)))
                    .thenReturn(mock(CloseableHttpClient.class));
            circuitBreakerStatic
                    .when(() -> CircuitBreaker.getInstance(any(StatusListConfig.class)))
                    .thenReturn(mock(CircuitBreaker.class));

            StatusListService first = StatusListServiceHolder.getOrCreate(session);
            StatusListService second = StatusListServiceHolder.getOrCreate(session);

            assertSame(first, second);
            assertSame(first, serviceConstruction.constructed().get(0));
            verify(session).enlistForClose(any(Provider.class));
        }
    }

    @Test
    void closeClosesSharedService() {
        stubSessionAttributes();
        try (MockedStatic<CustomHttpClient> httpClientStatic = mockStatic(CustomHttpClient.class);
                MockedStatic<CircuitBreaker> circuitBreakerStatic = mockStatic(CircuitBreaker.class);
                MockedConstruction<CryptoIdentityService> cryptoServiceConstruction =
                        mockConstruction(CryptoIdentityService.class, (mock, ctx) -> when(mock.getJwtToken(any()))
                                .thenReturn("token"));
                MockedConstruction<StatusListService> serviceConstruction = mockConstruction(StatusListService.class)) {

            httpClientStatic
                    .when(() -> CustomHttpClient.getHttpClient(any(StatusListConfig.class)))
                    .thenReturn(mock(CloseableHttpClient.class));
            circuitBreakerStatic
                    .when(() -> CircuitBreaker.getInstance(any(StatusListConfig.class)))
                    .thenReturn(mock(CircuitBreaker.class));

            StatusListService service = StatusListServiceHolder.getOrCreate(session);

            ArgumentCaptor<Provider> captor = ArgumentCaptor.forClass(Provider.class);
            verify(session).enlistForClose(captor.capture());
            captor.getValue().close();

            verify(service).close();
        }
    }
}
