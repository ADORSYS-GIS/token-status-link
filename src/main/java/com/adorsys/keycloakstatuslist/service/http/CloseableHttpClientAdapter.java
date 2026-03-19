package com.adorsys.keycloakstatuslist.service.http;

import java.io.IOException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;

/**
 * Adapter that wraps Apache HttpClient's CloseableHttpClient to implement our HttpClient interface.
 * This allows StatusListService to depend on the interface while using the concrete implementation.
 */
public class CloseableHttpClientAdapter implements HttpClient {

    private final CloseableHttpClient httpClient;

    public CloseableHttpClientAdapter(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public <T> T execute(HttpGet request, HttpClientResponseHandler<? extends T> responseHandler) throws IOException {
        return httpClient.execute(request, responseHandler);
    }

    @Override
    public <T> T execute(HttpPost request, HttpClientResponseHandler<? extends T> responseHandler) throws IOException {
        return httpClient.execute(request, responseHandler);
    }

    @Override
    public <T> T execute(HttpPatch request, HttpClientResponseHandler<? extends T> responseHandler) throws IOException {
        return httpClient.execute(request, responseHandler);
    }

    @Override
    public <T> T execute(ClassicHttpRequest request, HttpClientResponseHandler<? extends T> responseHandler)
            throws IOException {
        return httpClient.execute(request, responseHandler);
    }
}
