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

/**
 * Sealed interface representing a token validation request carrying the token string
 * plus HTTP request context (headers) through the validation pipeline.
 * <p>
 * This parameter object enables future features that require HTTP context during
 * token validation, such as:
 * <ul>
 *   <li>RFC 9068 {@code typ} header validation (per-issuer configuration)</li>
 *   <li>RFC 9449 DPoP sender-constrained token validation (requires the {@code DPoP} HTTP header)</li>
 * </ul>
 * <p>
 * Each permit type corresponds to a specific token pipeline, providing type safety
 * and preventing accidental misuse (e.g., passing an ID token request to the access
 * token pipeline).
 * <p>
 * Implementations are immutable and thread-safe.
 *
 * @since 1.0
 */
public sealed interface TokenValidationRequest
        permits AccessTokenRequest, IdTokenRequest, RefreshTokenRequest {

    /**
     * Returns the raw token string to validate.
     *
     * @return the token string, never null
     */
    String tokenString();

    /**
     * Returns the HTTP headers from the original request.
     * <p>
     * Header names are expected to be lowercase per RFC 9113 (HTTP/2) and RFC 7230 (HTTP/1.1).
     * The returned map is an unmodifiable defensive copy.
     *
     * @return immutable map of HTTP headers, never null (may be empty)
     */
    Map<String, List<String>> httpHeaders();
}
