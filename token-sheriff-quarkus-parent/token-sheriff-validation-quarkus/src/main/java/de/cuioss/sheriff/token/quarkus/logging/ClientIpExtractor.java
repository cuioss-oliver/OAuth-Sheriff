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

import jakarta.ws.rs.core.MultivaluedMap;
import lombok.experimental.UtilityClass;

import java.util.List;

/**
 * Utility class for extracting client IP addresses from HTTP headers.
 * Handles the complex logic of determining the original client IP address
 * through various proxy chains, CDN configurations, and load balancers.
 *
 * <p>This class follows 2024 industry standards for IP extraction, supporting
 * headers from major CDN providers (Cloudflare, Akamai, Fastly), load balancers,
 * and proxy configurations.</p>
 *
 * <p>The extraction follows a priority order from most trusted to least trusted
 * headers, with special handling for comma-separated values and RFC 7239 format.</p>
 *
 * <p><strong>Security Warning — Proxy Trust Model:</strong></p>
 * <ul>
 *   <li>The proxy headers inspected by this class (e.g. {@code X-Forwarded-For},
 *       {@code CF-Connecting-IP}) are <strong>only trustworthy when the application
 *       is deployed behind a trusted reverse proxy</strong> that overwrites or
 *       validates these headers before forwarding the request.</li>
 *   <li>In direct-client deployments (no reverse proxy), <strong>all proxy headers
 *       can be spoofed</strong> by the client, making the extracted IP unreliable
 *       for security decisions such as rate limiting or audit logging.</li>
 *   <li>The application should use Quarkus's proxy trust configuration
 *       ({@code quarkus.http.proxy.proxy-address-forwarding},
 *       {@code quarkus.http.proxy.trusted-proxies}) to limit which upstream
 *       addresses are allowed to set forwarding headers.</li>
 * </ul>
 *
 * @since 1.0
 */
@UtilityClass
public class ClientIpExtractor {

    /**
     * Standard proxy headers checked for client IP address extraction, in priority order.
     * Based on 2024 industry standards covering major CDNs, load balancers, and proxy configurations.
     */
    private static final String[] PROXY_HEADERS = {
            "X-Forwarded-For",       // Most common, de-facto standard
            "CF-Connecting-IP",      // Cloudflare (very common CDN)
            "True-Client-IP",        // Cloudflare Enterprise, Akamai CDN
            "X-Real-IP",             // Nginx style, widely used
            "Fastly-Client-IP",      // Fastly CDN
            "X-Client-IP",           // Microsoft style, various proxies
            "X-Originating-IP",      // Some proxy configurations
            "X-Original-Forwarded-For", // Nested proxy scenarios
            "X-Forwarded",           // Less common variant
            "X-Remote-IP",           // Alternative client IP header
            "X-Remote-Addr",         // Remote address variant
            "X-Cluster-Client-IP",   // Cluster environments
            "Remote-Addr"            // Basic proxy header
    };

    /**
     * Extracts the client IP address from HTTP headers, falling back to the provided
     * address (typically the Vert.x remote address) when no proxy headers are found.
     *
     * @param headers JAX-RS MultivaluedMap of HTTP headers
     * @param fallbackAddress the direct connection address to use when no proxy headers are present,
     *                        typically from {@code HttpServerRequest.remoteAddress().host()}.
     *                        May be {@code null}, in which case {@code "unknown"} is returned as final fallback.
     * @return The extracted client IP address
     */
    public static String extractClientIp(MultivaluedMap<String, String> headers, String fallbackAddress) {
        // Check standard headers first
        for (String headerName : PROXY_HEADERS) {
            String result = extractFromHeader(headers, headerName);
            if (result != null) {
                return result;
            }
        }

        // Special case: RFC 7239 Forwarded header (more complex parsing)
        String result = extractFromForwardedHeader(headers);
        if (result != null) {
            return result;
        }

        return fallbackAddress != null ? fallbackAddress : "unknown";
    }

    /**
     * Extracts IP address from a standard proxy header (MultivaluedMap version).
     * Handles comma-separated values by taking the first (original client) IP.
     *
     * @param headers MultivaluedMap of HTTP headers
     * @param headerName Name of the header to check
     * @return The extracted IP address, or null if not found/empty
     */
    private static String extractFromHeader(MultivaluedMap<String, String> headers, String headerName) {
        List<String> headerValues = headers.get(headerName);
        if (headerValues != null && !headerValues.isEmpty()) {
            String headerValue = headerValues.getFirst();
            if (headerValue != null && !headerValue.trim().isEmpty()) {
                // For comma-separated values, take the first (original client)
                return headerValue.split(",")[0].trim();
            }
        }
        return null;
    }

    /**
     * Extracts IP address from RFC 7239 Forwarded header (MultivaluedMap version).
     * Parses the complex "for=IP; proto=http" format.
     *
     * @param headers MultivaluedMap of HTTP headers
     * @return The extracted IP address, or null if not found/parseable
     */
    private static String extractFromForwardedHeader(MultivaluedMap<String, String> headers) {
        List<String> forwardedValues = headers.get("Forwarded");
        if (forwardedValues != null && !forwardedValues.isEmpty()) {
            String standardForwarded = forwardedValues.getFirst();
            if (standardForwarded != null && !standardForwarded.trim().isEmpty()) {
                // Parse "for=IP" from Forwarded header
                String[] parts = standardForwarded.split(";");
                for (String part : parts) {
                    String trimmed = part.trim();
                    if (trimmed.startsWith("for=")) {
                        return normalizeForwardedForValue(trimmed.substring(4));
                    }
                }
            }
        }
        return null;
    }

    /**
     * Normalizes an RFC 7239 {@code for=} node identifier to a bare address.
     * <p>
     * Handles the following forms without truncating IPv6 addresses:
     * <ul>
     *   <li>{@code "[2001:db8::17]:4711"} / {@code [2001:db8::17]} — bracketed IPv6,
     *       optionally with port: returns the bracket content</li>
     *   <li>{@code 192.0.2.43:47011} — IPv4 (single colon) with port: strips the port</li>
     *   <li>{@code 2001:db8::17} — bare IPv6 (multiple colons): returned unchanged</li>
     *   <li>Anything else (plain IPv4, obfuscated identifiers): returned unchanged</li>
     * </ul>
     *
     * @param forValue the raw value of the {@code for=} parameter, possibly quoted
     * @return the address without quotes, brackets, or port
     */
    private static String normalizeForwardedForValue(String forValue) {
        String value = forValue.trim();
        // Remove optional surrounding double quotes per RFC 7239
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
        }
        // Bracketed IPv6 form "[...]" with optional ":port" suffix
        if (value.startsWith("[")) {
            int closingBracket = value.indexOf(']');
            if (closingBracket > 0) {
                return value.substring(1, closingBracket);
            }
            return value; // malformed — return unchanged
        }
        // IPv4 (or hostname) with port: exactly one colon
        int firstColon = value.indexOf(':');
        if (firstColon >= 0 && firstColon == value.lastIndexOf(':')) {
            return value.substring(0, firstColon);
        }
        // Bare IPv6 (multiple colons) or plain address: return unchanged
        return value;
    }

}