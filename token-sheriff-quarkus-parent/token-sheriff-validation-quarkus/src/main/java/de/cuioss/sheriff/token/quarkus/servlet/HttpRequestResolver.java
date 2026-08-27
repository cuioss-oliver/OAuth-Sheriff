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

import java.util.List;
import java.util.Map;

/**
 * Interface for resolving HTTP request data within request contexts.
 *
 * <p>Implementations provide access to HTTP headers, request URI, and request method
 * from the current request context. If no request context is available, implementations
 * must throw {@link IllegalStateException}.</p>
 *
 * <p><strong>Context Dependency:</strong> When not in an appropriate request context (e.g., outside REST requests),
 * the CDI system will throw {@link jakarta.enterprise.inject.IllegalProductException} because the underlying
 * {@code @RequestScoped} HttpServerRequest producer cannot provide a valid instance. This is wrapped behavior -
 * implementations may throw {@link IllegalStateException} which gets wrapped by CDI.</p>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public interface HttpRequestResolver {

    /**
     * Resolves HTTP headers from the current request context as a Map with normalized header names.
     *
     * <p>Header field names must be normalized to lowercase for RFC compliance and consistent processing.</p>
     *
     * <p><strong>Header Name Normalization:</strong> According to RFC 7230 Section 3.2 (HTTP/1.1),
     * header field names are case-insensitive. RFC 9113 Section 8.1.2 (HTTP/2) requires header
     * field names to be converted to lowercase prior to encoding. Implementations must normalize
     * all header names to lowercase using {@link java.util.Locale#ROOT} to ensure consistent,
     * locale-independent processing regardless of the underlying HTTP protocol version.</p>
     *
     * @return Map of HTTP headers with lowercase header names from the current context
     * @throws jakarta.enterprise.inject.IllegalProductException if not in an active request context
     *                               (CDI wraps underlying exceptions when @RequestScoped producer fails)
     * @throws IllegalStateException if the infrastructure is not available to resolve headers
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7230#section-3.2">RFC 7230 Section 3.2: Header Fields</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9113#section-8.1.2">RFC 9113 Section 8.1.2: HTTP Header Fields</a>
     */
    Map<String, List<String>> resolveHeaderMap() throws IllegalStateException;

    /**
     * Resolves the full HTTP request URI (scheme + host + path) from the current context.
     * Used for DPoP htu claim validation per RFC 9449.
     *
     * @return the request URI as a string, or null if not available
     */
    String resolveRequestUri();

    /**
     * Resolves the HTTP method from the current context.
     * Used for DPoP htm claim validation per RFC 9449.
     *
     * @return the HTTP method (GET, POST, etc.), or null if not available
     */
    String resolveRequestMethod();
}
