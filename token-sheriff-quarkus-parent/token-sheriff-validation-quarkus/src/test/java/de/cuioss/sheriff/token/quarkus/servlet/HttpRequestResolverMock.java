/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.token.quarkus.servlet;

import java.util.*;

/**
 * Mock implementation of {@link HttpRequestResolver} for testing purposes.
 *
 * <p>This mock manages headers, request URI, and request method directly
 * for convenient test setup.</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * HttpRequestResolverMock mock = new HttpRequestResolverMock();
 * mock.setBearerToken("mytoken123")
 *     .setHeader("X-Custom-Header", "value1")
 *     .addHeader("X-Custom-Header", "value2")
 *     .setMethod("POST")
 *     .setRequestURI("/api/test");
 *
 * Map<String, List<String>> headers = mock.resolveHeaderMap();
 *
 * // Simulate absence of request context
 * mock.setRequestContextAvailable(false);
 * assertThrows(IllegalStateException.class, () -> mock.resolveHeaderMap());
 * }</pre>
 *
 * @author Oliver Wolff
 */
public class HttpRequestResolverMock implements HttpRequestResolver {

    private final Map<String, List<String>> headers = new LinkedHashMap<>();
    private boolean requestContextAvailable = true;
    private String method = "GET";
    private String requestUri = "/";

    @Override
    public Map<String, List<String>> resolveHeaderMap() throws IllegalStateException {
        checkContext();
        Map<String, List<String>> result = new HashMap<>();
        for (var entry : headers.entrySet()) {
            result.put(entry.getKey().toLowerCase(Locale.ROOT), new ArrayList<>(entry.getValue()));
        }
        return result;
    }

    @Override
    public String resolveRequestUri() {
        checkContext();
        return requestUri;
    }

    @Override
    public String resolveRequestMethod() {
        checkContext();
        return method;
    }

    private void checkContext() {
        if (!requestContextAvailable) {
            throw new IllegalStateException("Request context not available - mock configured to simulate absent context");
        }
    }

    // Configuration methods

    public HttpRequestResolverMock setRequestContextAvailable(boolean available) {
        this.requestContextAvailable = available;
        return this;
    }

    public boolean isRequestContextAvailable() {
        return requestContextAvailable;
    }

    public HttpRequestResolverMock setHeader(String name, String value) {
        headers.put(name, new ArrayList<>(List.of(value)));
        return this;
    }

    public HttpRequestResolverMock addHeader(String name, String value) {
        headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        return this;
    }

    public HttpRequestResolverMock removeHeader(String name) {
        headers.remove(name);
        return this;
    }

    public HttpRequestResolverMock clearHeaders() {
        headers.clear();
        return this;
    }

    public HttpRequestResolverMock setBearerToken(String token) {
        return setHeader("Authorization", "Bearer " + token);
    }

    public HttpRequestResolverMock setMethod(String method) {
        this.method = method;
        return this;
    }

    public HttpRequestResolverMock setRequestURI(String requestUri) {
        this.requestUri = requestUri;
        return this;
    }

    // Convenience factory methods

    public static HttpRequestResolverMock withBearerToken(String token) {
        return new HttpRequestResolverMock()
                .setBearerToken(token)
                .setMethod("GET")
                .setRequestURI("/api/protected");
    }

    public static HttpRequestResolverMock withoutRequestContext() {
        return new HttpRequestResolverMock()
                .setRequestContextAvailable(false);
    }

    public static HttpRequestResolverMock withRequest(String method, String requestUri) {
        return new HttpRequestResolverMock()
                .setMethod(method)
                .setRequestURI(requestUri)
                .setHeader("Content-Type", "application/json")
                .setHeader("Accept", "application/json");
    }

    public HttpRequestResolverMock reset() {
        headers.clear();
        method = "GET";
        requestUri = "/";
        requestContextAvailable = true;
        return this;
    }
}
