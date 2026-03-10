package com.adorsys.keycloakstatuslist.service;

import com.adorsys.keycloakstatuslist.config.StatusListConfig;
import org.jboss.logging.Logger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Simple circuit breaker implementation to protect against repeated failures
 * when calling external services.
 * 
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Too many failures, requests fail fast
 * - HALF_OPEN: Testing if service recovered, limited requests allowed
 */
public class CircuitBreaker {
    
    private static final Logger logger = Logger.getLogger(CircuitBreaker.class);
    private static final ConcurrentHashMap<String, CircuitBreaker> INSTANCES = new ConcurrentHashMap<>();
    
    private enum State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }
    
    private final String name;
    private final int failureThreshold;
    private final long windowMillis;
    private final long cooldownMillis;
    
    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicLong windowStartTime = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong lastFailureTime = new AtomicLong(0);
    
    /**
     * Creates a new circuit breaker.
     *
     * @param name identifier for logging
     * @param failureThreshold number of failures/timeouts before opening circuit
     * @param windowSeconds time window for counting failures
     * @param cooldownSeconds time before attempting recovery
     */
    private CircuitBreaker(String name, int failureThreshold,
                          int windowSeconds, int cooldownSeconds) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.windowMillis = windowSeconds * 1000L;
        this.cooldownMillis = cooldownSeconds * 1000L;
        
        logger.infof("Circuit breaker '%s' initialized: failureThreshold=%d, " +
                "window=%ds, cooldown=%ds", 
                name, failureThreshold, windowSeconds, cooldownSeconds);
    }
    
    /**
     * Returns a shared CircuitBreaker instance for the given realm configuration.
     * Threshold, window and cooldown are taken from the config (single source of truth).
     * The instance is keyed by realm ID so that all callers for the same realm share the same circuit breaker.
     *
     * @param config the status list configuration for the realm (provides realm ID and circuit breaker settings)
     * @return the shared CircuitBreaker for this realm
     */
    public static CircuitBreaker getInstance(StatusListConfig config) {
        String name = "CircuitBreaker-" + config.getRealmId();
        return getInstance(name,
                config.getCircuitBreakerFailureThreshold(),
                config.getCircuitBreakerWindowSeconds(),
                config.getCircuitBreakerCooldownSeconds());
    }

    /**
     * Returns a shared CircuitBreaker instance for the given name and parameters.
     * Used internally by {@link #getInstance(StatusListConfig)}.
     */
    private static CircuitBreaker getInstance(
            String name, int failureThreshold, int windowSeconds, int cooldownSeconds) {
        return INSTANCES.computeIfAbsent(
                name,
                key -> new CircuitBreaker(key, failureThreshold, windowSeconds, cooldownSeconds));
    }
    
    /**
     * Checks if a request should be allowed through the circuit breaker.
     *
     * @throws CircuitBreakerOpenException if the circuit is open
     */
    public void checkState() throws CircuitBreakerOpenException {
        State currentState = state.get();
        long now = System.currentTimeMillis();
        
        // Check if window has expired and reset counters
        if (now - windowStartTime.get() > windowMillis) {
            resetWindow();
        }
        
        switch (currentState) {
            case OPEN:
                // Check if cooldown period has passed
                if (now - lastFailureTime.get() >= cooldownMillis) {
                    // Try half-open state
                    if (state.compareAndSet(State.OPEN, State.HALF_OPEN)) {
                        logger.infof("Circuit breaker '%s' transitioning to HALF_OPEN", name);
                    }
                } else {
                    // Still in cooldown, fail fast
                    throw new CircuitBreakerOpenException(
                        String.format("Circuit breaker '%s' is OPEN. Failing fast.", name));
                }
                break;
                
            case HALF_OPEN:
                logger.debugf("Circuit breaker '%s' in HALF_OPEN, allowing test request", name);
                break;
            default:
                // CLOSED: allow request, no action needed
                break;
        }
    }
    
    /**
     * Records a successful operation.
     */
    public void recordSuccess() {
        State currentState = state.get();
        
        if (currentState == State.HALF_OPEN) {
            // Success in half-open state, close the circuit
            if (state.compareAndSet(State.HALF_OPEN, State.CLOSED)) {
                resetCounters();
                logger.infof("Circuit breaker '%s' transitioning to CLOSED after successful test", name);
            }
        }
    }
    
    /**
     * Records a failed operation.
     */
    public void recordFailure() {
        long now = System.currentTimeMillis();
        lastFailureTime.set(now);
        
        State currentState = state.get();
        
        if (currentState == State.HALF_OPEN) {
            if (state.compareAndSet(State.HALF_OPEN, State.OPEN)) {
                logger.warnf("Circuit breaker '%s' transitioning back to OPEN after failed test", name);
            }
            return;
        }
        
        int failures = failureCount.incrementAndGet();
        logger.debugf("Circuit breaker '%s' recorded failure %d/%d", name, failures, failureThreshold);
        
        if (failures >= failureThreshold) {
            if (state.compareAndSet(State.CLOSED, State.OPEN)) {
                logger.errorf("Circuit breaker '%s' OPENED after %d failures", name, failures);
            }
        }
    }
    
    /**
     * Records a timeout operation. Timeouts are treated the same as failures.
     */
    public void recordTimeout() {
        logger.debugf("Circuit breaker '%s' recorded timeout (treated as failure)", name);
        recordFailure();
    }
    
    /**
     * Resets the time window and counters.
     */
    private void resetWindow() {
        long now = System.currentTimeMillis();
        windowStartTime.set(now);
        failureCount.set(0);
        logger.debugf("Circuit breaker '%s' reset window", name);
    }
    
    /**
     * Resets all counters.
     */
    private void resetCounters() {
        failureCount.set(0);
        windowStartTime.set(System.currentTimeMillis());
    }
    
    /**
     * Gets the current state of the circuit breaker.
     *
     * @return the current state
     */
    public String getState() {
        return state.get().name();
    }
    
    /**
     * Gets the current failure count.
     *
     * @return the failure count
     */
    public int getFailureCount() {
        return failureCount.get();
    }
        
    /**
     * Exception thrown when circuit breaker is open.
     */
    public static class CircuitBreakerOpenException extends Exception {
        public CircuitBreakerOpenException(String message) {
            super(message);
        }
    }
}

