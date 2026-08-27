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
package de.cuioss.sheriff.token.validation.domain.context;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Request object for ID token validation, carrying the token string and HTTP headers.
 * <p>
 * This record is immutable and thread-safe. The HTTP headers map is defensively copied
 * at construction time.
 * <p>
 * Usage:
 * <pre>
 * // Without HTTP headers (typical scenario)
 * IdTokenRequest request = IdTokenRequest.of(tokenString);
 *
 * // With HTTP headers
 * IdTokenRequest request = new IdTokenRequest(tokenString, httpHeaders);
 * </pre>
 *
 * @param tokenString the raw token string, must not be null
 * @param httpHeaders the HTTP headers from the original request, defensively copied
 * @since 1.0
 */
public record IdTokenRequest(String tokenString, Map<String, List<String>> httpHeaders)
        implements TokenValidationRequest {

    /**
     * Compact constructor that validates inputs and creates defensive copies.
     *
     * @param tokenString the raw token string, must not be null
     * @param httpHeaders the HTTP headers, must not be null (may be empty)
     */
    public IdTokenRequest {
        Objects.requireNonNull(tokenString, "tokenString must not be null");
        Objects.requireNonNull(httpHeaders, "httpHeaders must not be null");
        httpHeaders = Map.copyOf(httpHeaders);
    }

    /**
     * Convenience factory for creating a request without HTTP headers.
     * <p>
     * Suitable for test scenarios or callers that do not have access to HTTP context.
     *
     * @param tokenString the raw token string, must not be null
     * @return a new IdTokenRequest with an empty header map
     */
    public static IdTokenRequest of(String tokenString) {
        return new IdTokenRequest(tokenString, Map.of());
    }
}
