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
package de.cuioss.sheriff.token.quarkus.logging;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for ClientIpExtractor utility class.
 * Covers various proxy header scenarios, CDN configurations, and edge cases.
 */
class ClientIpExtractorTest {

    @ParameterizedTest(name = "Header ''{0}'' with value ''{1}'' should extract IP ''{2}''")
    @CsvSource({
            "X-Forwarded-For,          192.168.1.100,                              192.168.1.100",
            "X-Forwarded-For,          '203.0.113.1,198.51.100.101,198.51.100.102', 203.0.113.1",
            "CF-Connecting-IP,         203.0.113.50,                               203.0.113.50",
            "True-Client-IP,           198.51.100.200,                             198.51.100.200",
            "X-Real-IP,                10.0.0.100,                                 10.0.0.100",
            "Fastly-Client-IP,         172.16.0.50,                                172.16.0.50",
            "X-Client-IP,              192.168.100.25,                              192.168.100.25",
            "X-Originating-IP,         10.1.1.1,                                   10.1.1.1",
            "Forwarded,                for=203.0.113.1; proto=https,               203.0.113.1",
            "Forwarded,                'for=\"203.0.113.1\"; proto=https',         203.0.113.1",
            "Forwarded,                for=[2001:db8::1]; proto=https,             2001:db8::1",
            "Forwarded,                'for=\"[2001:db8::17]:4711\"; proto=https', 2001:db8::17",
            "Forwarded,                'for=\"[2001:db8::17]\"; proto=https',      2001:db8::17",
            "Forwarded,                for=2001:db8::1; proto=https,               2001:db8::1",
            "Forwarded,                for=203.0.113.1:8080; proto=https,          203.0.113.1",
            "Forwarded,                'for=\"203.0.113.1:8080\"; proto=https',    203.0.113.1",
            "X-Forwarded-For,          '  192.168.1.1  ',                          192.168.1.1",
            "X-Forwarded-For,          2001:db8::1,                                2001:db8::1",
            "X-Forwarded-For,          '203.0.113.1,2001:db8::1',                  203.0.113.1",
    })
    @DisplayName("Should extract IP from single header")
    void shouldExtractIpFromSingleHeader(String headerName, String headerValue, String expectedIp) {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle(headerName, headerValue);

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals(expectedIp, result);
    }

    @Test
    @DisplayName("Should return malformed bracketed IPv6 value unchanged")
    void shouldReturnMalformedBracketValueUnchanged() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Forwarded", "for=\"[2001:db8::1\"; proto=https");

        // No closing bracket: the value cannot be normalized and is returned unchanged
        assertEquals("[2001:db8::1", ClientIpExtractor.extractClientIp(headers, null));
    }

    @Test
    @DisplayName("Should return unknown when no headers provided")
    void shouldReturnUnknownWhenNoHeaders() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("unknown", result);
    }

    @Test
    @DisplayName("Should prioritize CF-Connecting-IP over X-Real-IP")
    void shouldPrioritizeCloudflareOverXRealIP() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("CF-Connecting-IP", "203.0.113.50");
        headers.putSingle("X-Real-IP", "10.0.0.1");

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("203.0.113.50", result);
    }

    @Test
    @DisplayName("Should handle empty header values")
    void shouldHandleEmptyHeaderValues() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("X-Forwarded-For", "");
        headers.putSingle("CF-Connecting-IP", "   ");
        headers.putSingle("X-Real-IP", "192.168.1.1");

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("192.168.1.1", result);
    }

    @Test
    @DisplayName("Should follow priority order correctly")
    void shouldFollowPriorityOrder() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Remote-Addr", "10.0.0.1");           // Lowest priority
        headers.putSingle("X-Real-IP", "10.0.0.2");            // Medium priority
        headers.putSingle("CF-Connecting-IP", "10.0.0.3");     // High priority
        headers.putSingle("X-Forwarded-For", "10.0.0.4");      // Highest priority

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("10.0.0.4", result); // Should pick X-Forwarded-For (highest priority)
    }

    @Test
    @DisplayName("Should handle comma-separated values in multiple headers")
    void shouldHandleCommaSeparatedInMultipleHeaders() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("X-Real-IP", "10.0.0.1,10.0.0.2");
        headers.putSingle("X-Forwarded-For", "203.0.113.1,198.51.100.1");

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("203.0.113.1", result); // Should pick first from X-Forwarded-For
    }

    @Test
    @DisplayName("Should handle malformed Forwarded header gracefully")
    void shouldHandleMalformedForwardedHeader() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Forwarded", "malformed=value; not-for=something");
        headers.putSingle("X-Real-IP", "10.0.0.1");

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("10.0.0.1", result); // Should fall back to X-Real-IP
    }

    @Test
    @DisplayName("Should work with MultivaluedMap directly from JAX-RS")
    void shouldWorkWithMultivaluedMap() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("CF-Connecting-IP", "203.0.113.100");
        headers.putSingle("X-Real-IP", "10.0.0.1");

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("203.0.113.100", result); // Should prioritize CF-Connecting-IP
    }

    @Test
    @DisplayName("Should return fallbackAddress when no proxy headers exist")
    void shouldReturnFallbackAddressWhenNoProxyHeaders() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        String result = ClientIpExtractor.extractClientIp(headers, "192.168.1.50");

        assertEquals("192.168.1.50", result);
    }

    @Test
    @DisplayName("Should return unknown when no proxy headers and fallbackAddress is null")
    void shouldReturnUnknownWhenNoProxyHeadersAndNullFallback() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("unknown", result);
    }

    @Test
    @DisplayName("Should prioritize proxy headers over fallbackAddress")
    void shouldPrioritizeProxyHeadersOverFallback() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("X-Forwarded-For", "203.0.113.1");

        String result = ClientIpExtractor.extractClientIp(headers, "10.0.0.99");

        assertEquals("203.0.113.1", result);
    }

    @Test
    @DisplayName("Should handle MultivaluedMap with multiple values")
    void shouldHandleMultivaluedMapWithMultipleValues() {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("X-Forwarded-For", "203.0.113.1,198.51.100.1");
        headers.add("X-Forwarded-For", "10.0.0.1"); // Second value should be ignored

        String result = ClientIpExtractor.extractClientIp(headers, null);

        assertEquals("203.0.113.1", result); // Should take first value, then first IP from comma-separated
    }
}