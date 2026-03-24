package com.adorsys.keycloakstatuslist.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

class CircuitBreakerTest {

    @BeforeEach
    void resetInstances() throws Exception {
        Field instancesField = CircuitBreaker.class.getDeclaredField("INSTANCES");
        instancesField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, CircuitBreaker> instances = (Map<String, CircuitBreaker>) instancesField.get(null);
        instances.clear();
    }

    @Test
    void shouldReturnSameInstanceForSameRealm() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("realm-a");
        StatusListConfig config = new StatusListConfig(realm);

        CircuitBreaker first = CircuitBreaker.getInstance(config);
        CircuitBreaker second = CircuitBreaker.getInstance(config);

        assertEquals(first, second);
    }

    @Test
    void shouldOpenAfterFailureThresholdAndFailFast() throws Exception {
        CircuitBreaker breaker = createBreaker("open-test", 2, 60, 30);

        breaker.recordFailure();
        breaker.recordFailure();

        assertEquals("OPEN", breaker.getState());
        assertThrows(CircuitBreaker.CircuitBreakerOpenException.class, breaker::checkState);
    }

    @Test
    void shouldTransitionToHalfOpenThenClosedAfterSuccess() throws Exception {
        CircuitBreaker breaker = createBreaker("half-open-success", 1, 60, 0);

        breaker.recordFailure();
        assertEquals("OPEN", breaker.getState());

        breaker.checkState();
        assertEquals("HALF_OPEN", breaker.getState());

        breaker.recordSuccess();
        assertEquals("CLOSED", breaker.getState());
        assertEquals(0, breaker.getFailureCount());
    }

    @Test
    void shouldTransitionBackToOpenWhenHalfOpenRequestFails() throws Exception {
        CircuitBreaker breaker = createBreaker("half-open-failure", 1, 60, 0);

        breaker.recordFailure();
        breaker.checkState();
        assertEquals("HALF_OPEN", breaker.getState());

        breaker.recordFailure();
        assertEquals("OPEN", breaker.getState());
    }

    @Test
    void shouldTreatTimeoutAsFailure() {
        CircuitBreaker breaker = createBreaker("timeout", 3, 60, 30);

        breaker.recordTimeout();

        assertEquals(1, breaker.getFailureCount());
        assertEquals("CLOSED", breaker.getState());
    }

    @Test
    void shouldResetFailureWindowAfterExpiry() throws Exception {
        CircuitBreaker breaker = createBreaker("window-reset", 3, 0, 30);

        breaker.recordFailure();
        assertEquals(1, breaker.getFailureCount());

        Thread.sleep(5);
        breaker.checkState();

        assertEquals(0, breaker.getFailureCount());
    }

    private CircuitBreaker createBreaker(String name, int failureThreshold, int windowSeconds, int cooldownSeconds) {
        try {
            Method getInstance = CircuitBreaker.class.getDeclaredMethod(
                    "getInstance", String.class, int.class, int.class, int.class);
            getInstance.setAccessible(true);
            return (CircuitBreaker) getInstance.invoke(null, name, failureThreshold, windowSeconds, cooldownSeconds);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create test circuit breaker", e);
        }
    }
}
