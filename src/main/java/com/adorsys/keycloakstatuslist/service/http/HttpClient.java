package com.adorsys.keycloakstatuslist.service.http;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;

import java.io.IOException;

/**
 * Interface for HTTP client operations. Allows alternative HTTP client implementations to be
 * substituted (e.g., for testing, different HTTP libraries, or custom retry strategies).
 */
public interface HttpClient {

    /**
     * Executes an HTTP GET request.
     *
     * @param request the HTTP GET request
     * @param responseHandler the response handler
     * @param <T> the response type
     * @return the response object
     * @throws IOException if the request fails
     */
    <T> T execute(HttpGet request, HttpClientResponseHandler<? extends T> responseHandler)
            throws IOException;

    /**
     * Executes an HTTP POST request.
     *
     * @param request the HTTP POST request
     * @param responseHandler the response handler
     * @param <T> the response type
     * @return the response object
     * @throws IOException if the request fails
     */
    <T> T execute(HttpPost request, HttpClientResponseHandler<? extends T> responseHandler)
            throws IOException;

    /**
     * Executes an HTTP PATCH request.
     *
     * @param request the HTTP PATCH request
     * @param responseHandler the response handler
     * @param <T> the response type
     * @return the response object
     * @throws IOException if the request fails
     */
    <T> T execute(HttpPatch request, HttpClientResponseHandler<? extends T> responseHandler)
            throws IOException;

    /**
     * Executes a generic HTTP request.
     *
     * @param request the HTTP request
     * @param responseHandler the response handler
     * @param <T> the response type
     * @return the response object
     * @throws IOException if the request fails
     */
    <T> T execute(ClassicHttpRequest request, HttpClientResponseHandler<? extends T> responseHandler)
            throws IOException;
}

