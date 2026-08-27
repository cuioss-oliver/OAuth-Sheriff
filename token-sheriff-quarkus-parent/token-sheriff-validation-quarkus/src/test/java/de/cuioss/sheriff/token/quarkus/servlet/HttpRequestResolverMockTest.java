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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link HttpRequestResolverMock}.
 *
 * @author Oliver Wolff
 */
@DisplayName("HttpRequestResolverMock Tests")
class HttpRequestResolverMockTest {

    private HttpRequestResolverMock mock;

    @BeforeEach
    void setUp() {
        mock = new HttpRequestResolverMock();
    }

    @Test
    @DisplayName("Should return header map with lowercase header names")
    void shouldReturnHeaderMapWithLowercaseNames() {
        mock.setHeader("Authorization", "Bearer token123");
        mock.setHeader("CONTENT-TYPE", "application/json");
        mock.setHeader("Accept", "application/json");
        mock.addHeader("X-CUSTOM-HEADER", "value1");
        mock.addHeader("X-CUSTOM-HEADER", "value2");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();

        // All header names should be lowercase
        assertTrue(headerMap.containsKey("authorization"));
        assertTrue(headerMap.containsKey("content-type"));
        assertTrue(headerMap.containsKey("accept"));
        assertTrue(headerMap.containsKey("x-custom-header"));

        // Original case should not exist
        assertFalse(headerMap.containsKey("Authorization"));
        assertFalse(headerMap.containsKey("CONTENT-TYPE"));
        assertFalse(headerMap.containsKey("Accept"));
        assertFalse(headerMap.containsKey("X-CUSTOM-HEADER"));

        // Values should be preserved
        assertEquals("Bearer token123", headerMap.get("authorization").getFirst());
        assertEquals("application/json", headerMap.get("content-type").getFirst());
        assertEquals("application/json", headerMap.get("accept").getFirst());
        assertEquals(2, headerMap.get("x-custom-header").size());
        assertTrue(headerMap.get("x-custom-header").contains("value1"));
        assertTrue(headerMap.get("x-custom-header").contains("value2"));
    }

    @Test
    @DisplayName("Should return request URI and method with set values")
    void shouldReturnRequestUriAndMethod() {
        mock.setMethod("POST")
                .setRequestURI("/api/users");

        assertEquals("POST", mock.resolveRequestMethod());
        assertEquals("/api/users", mock.resolveRequestUri());
    }

    @Test
    @DisplayName("Should return default request URI and method")
    void shouldReturnDefaultRequestUriAndMethod() {
        assertEquals("GET", mock.resolveRequestMethod());
        assertEquals("/", mock.resolveRequestUri());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when context is not available for resolveHeaderMap")
    void shouldThrowForHeaderMapWhenContextNotAvailable() {
        mock.setRequestContextAvailable(false);
        assertThrows(IllegalStateException.class, () -> mock.resolveHeaderMap());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when context is not available for resolveRequestUri")
    void shouldThrowForRequestUriWhenContextNotAvailable() {
        mock.setRequestContextAvailable(false);
        assertThrows(IllegalStateException.class, () -> mock.resolveRequestUri());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when context is not available for resolveRequestMethod")
    void shouldThrowForRequestMethodWhenContextNotAvailable() {
        mock.setRequestContextAvailable(false);
        assertThrows(IllegalStateException.class, () -> mock.resolveRequestMethod());
    }

    @Test
    @DisplayName("Should support header manipulation methods")
    void shouldSupportHeaderManipulationMethods() {
        mock.setHeader("Authorization", "Bearer token123")
                .addHeader("X-Custom", "value1")
                .addHeader("X-Custom", "value2")
                .setHeader("Content-Type", "application/json");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();

        assertEquals("Bearer token123", headerMap.get("authorization").getFirst());
        assertEquals("application/json", headerMap.get("content-type").getFirst());
        assertEquals(2, headerMap.get("x-custom").size());
        assertTrue(headerMap.get("x-custom").contains("value1"));
        assertTrue(headerMap.get("x-custom").contains("value2"));
    }

    @Test
    @DisplayName("Should support header removal and clearing")
    void shouldSupportHeaderRemovalAndClearing() {
        mock.setHeader("Header1", "value1")
                .setHeader("Header2", "value2")
                .setHeader("Header3", "value3");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();
        assertEquals(3, headerMap.size());

        mock.removeHeader("Header2");
        headerMap = mock.resolveHeaderMap();
        assertFalse(headerMap.containsKey("header2"));
        assertTrue(headerMap.containsKey("header1"));
        assertTrue(headerMap.containsKey("header3"));

        mock.clearHeaders();
        headerMap = mock.resolveHeaderMap();
        assertTrue(headerMap.isEmpty());
    }

    @Test
    @DisplayName("Should support bearer token convenience method")
    void shouldSupportBearerTokenConvenienceMethod() {
        mock.setBearerToken("mytoken123");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();
        assertEquals("Bearer mytoken123", headerMap.get("authorization").getFirst());
    }

    @Test
    @DisplayName("Should support static factory method for bearer token")
    void shouldSupportStaticFactoryMethodForBearerToken() {
        HttpRequestResolverMock bearerMock = HttpRequestResolverMock.withBearerToken("token123");

        Map<String, List<String>> headerMap = bearerMock.resolveHeaderMap();
        assertEquals("Bearer token123", headerMap.get("authorization").getFirst());
        assertEquals("GET", bearerMock.resolveRequestMethod());
        assertEquals("/api/protected", bearerMock.resolveRequestUri());
    }

    @Test
    @DisplayName("Should support static factory method for no request context")
    void shouldSupportStaticFactoryMethodForNoRequestContext() {
        HttpRequestResolverMock noContextMock = HttpRequestResolverMock.withoutRequestContext();

        assertThrows(IllegalStateException.class, noContextMock::resolveHeaderMap);
        assertThrows(IllegalStateException.class, noContextMock::resolveRequestUri);
        assertThrows(IllegalStateException.class, noContextMock::resolveRequestMethod);
        assertFalse(noContextMock.isRequestContextAvailable());
    }

    @Test
    @DisplayName("Should support static factory method for request")
    void shouldSupportStaticFactoryMethodForRequest() {
        HttpRequestResolverMock requestMock = HttpRequestResolverMock.withRequest("POST", "/api/data");

        assertEquals("POST", requestMock.resolveRequestMethod());
        assertEquals("/api/data", requestMock.resolveRequestUri());

        Map<String, List<String>> headerMap = requestMock.resolveHeaderMap();
        assertEquals("application/json", headerMap.get("content-type").getFirst());
        assertEquals("application/json", headerMap.get("accept").getFirst());
    }

    @Test
    @DisplayName("Should support reset functionality")
    void shouldSupportResetFunctionality() {
        mock.setBearerToken("token123")
                .setMethod("POST")
                .setRequestURI("/api/test")
                .setHeader("X-Custom", "value")
                .setRequestContextAvailable(false);

        mock.reset();

        // Should be reset to defaults
        assertEquals("GET", mock.resolveRequestMethod());
        assertEquals("/", mock.resolveRequestUri());
        assertTrue(mock.resolveHeaderMap().isEmpty());
        assertTrue(mock.isRequestContextAvailable());
    }

    @Test
    @DisplayName("Should support method chaining")
    void shouldSupportMethodChaining() {
        HttpRequestResolverMock result = mock
                .setHeader("Authorization", "Bearer token123")
                .addHeader("X-Custom", "value1")
                .setBearerToken("newtoken")
                .setMethod("PUT")
                .setRequestURI("/api/update")
                .setRequestContextAvailable(true)
                .clearHeaders()
                .removeHeader("NonExistent");

        assertSame(mock, result);
    }

    @Test
    @DisplayName("Should maintain state consistency")
    void shouldMaintainStateConsistency() {
        mock.setRequestContextAvailable(true);
        assertTrue(mock.isRequestContextAvailable());
        assertDoesNotThrow(() -> mock.resolveHeaderMap());

        mock.setRequestContextAvailable(false);
        assertFalse(mock.isRequestContextAvailable());
        assertThrows(IllegalStateException.class, () -> mock.resolveHeaderMap());

        mock.setRequestContextAvailable(true);
        assertTrue(mock.isRequestContextAvailable());
        assertDoesNotThrow(() -> mock.resolveHeaderMap());
    }

    @Test
    @DisplayName("Should maintain header value ordering")
    void shouldMaintainHeaderValueOrdering() {
        mock.addHeader("X-Test", "first");
        mock.addHeader("X-Test", "second");
        mock.addHeader("X-Test", "third");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();

        List<String> values = headerMap.get("x-test");
        assertNotNull(values);
        assertEquals(3, values.size());
        assertEquals("first", values.getFirst());
        assertEquals("second", values.get(1));
        assertEquals("third", values.get(2));
    }

    @Test
    @DisplayName("Should support common HTTP headers in various cases")
    void shouldSupportCommonHttpHeadersInVariousCases() {
        mock.setHeader("Content-Length", "1024");
        mock.setHeader("CACHE-CONTROL", "no-cache");
        mock.setHeader("user-agent", "Test/1.0");
        mock.setHeader("X-Forwarded-For", "192.168.1.1");

        Map<String, List<String>> headerMap = mock.resolveHeaderMap();

        assertEquals("1024", headerMap.get("content-length").getFirst());
        assertEquals("no-cache", headerMap.get("cache-control").getFirst());
        assertEquals("Test/1.0", headerMap.get("user-agent").getFirst());
        assertEquals("192.168.1.1", headerMap.get("x-forwarded-for").getFirst());
    }
}
