package com.adorsys.keycloakstatuslist.service;

import org.jboss.logging.Logger;

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
    
    private enum State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }
    
    private final String name;
    private final int failureThreshold;
    private final int timeoutThreshold;
    private final long windowMillis;
    private final long cooldownMillis;
    
    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicInteger timeoutCount = new AtomicInteger(0);
    private final AtomicLong windowStartTime = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong lastFailureTime = new AtomicLong(0);
    
    /**
     * Creates a new circuit breaker.
     *
     * @param name identifier for logging
     * @param failureThreshold number of failures before opening circuit
     * @param timeoutThreshold number of timeouts before considering as failure
     * @param windowSeconds time window for counting failures
     * @param cooldownSeconds time before attempting recovery
     */
    public CircuitBreaker(String name, int failureThreshold, int timeoutThreshold, 
                         int windowSeconds, int cooldownSeconds) {
        this.name = name;
        this.failureThreshold = failureThreshold;
        this.timeoutThreshold = timeoutThreshold;
        this.windowMillis = windowSeconds * 1000L;
        this.cooldownMillis = cooldownSeconds * 1000L;
        
        logger.infof("Circuit breaker '%s' initialized: failureThreshold=%d, timeoutThreshold=%d, " +
                "window=%ds, cooldown=%ds", 
                name, failureThreshold, timeoutThreshold, windowSeconds, cooldownSeconds);
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
            case CLOSED:
                // Allow request
                break;
                
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
                // Allow limited requests to test recovery
                logger.debugf("Circuit breaker '%s' in HALF_OPEN, allowing test request", name);
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
        } else if (currentState == State.CLOSED) {
            // Normal success, optionally reset failure count
            // We keep track within the window, so no action needed here
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
            // Failure in half-open state, reopen the circuit
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
     * Records a timeout operation.
     */
    public void recordTimeout() {
        int timeouts = timeoutCount.incrementAndGet();
        logger.debugf("Circuit breaker '%s' recorded timeout %d/%d", name, timeouts, timeoutThreshold);
        
        if (timeouts >= timeoutThreshold) {
            // Treat accumulated timeouts as a failure
            recordFailure();
            timeoutCount.set(0); // Reset timeout counter after converting to failure
        }
    }
    
    /**
     * Resets the time window and counters.
     */
    private void resetWindow() {
        long now = System.currentTimeMillis();
        windowStartTime.set(now);
        failureCount.set(0);
        timeoutCount.set(0);
        logger.debugf("Circuit breaker '%s' reset window", name);
    }
    
    /**
     * Resets all counters.
     */
    private void resetCounters() {
        failureCount.set(0);
        timeoutCount.set(0);
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
     * Gets the current timeout count.
     *
     * @return the timeout count
     */
    public int getTimeoutCount() {
        return timeoutCount.get();
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

