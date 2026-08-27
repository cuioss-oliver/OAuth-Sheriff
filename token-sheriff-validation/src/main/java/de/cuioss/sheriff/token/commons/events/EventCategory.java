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
package de.cuioss.sheriff.token.commons.events;

/**
 * Categorizes security events by their type and impact.
 * <p>
 * This enum is used to group security events into categories that can be mapped
 * to appropriate HTTP status codes or other response mechanisms.
 * <p>
 * The categories are:
 * <ul>
 *   <li>InvalidStructure: For malformed tokens, size violations, etc. (typically thrown by NonValidatingJwtParser or TokenHeaderValidator). Usually maps to HTTP 401.</li>
 *   <li>InvalidSignature: For signature verification failures (typically thrown by TokenSignatureValidator). Usually maps to HTTP 401.</li>
 *   <li>SemanticIssues: For semantic validation failures (typically thrown by TokenClaimValidator, e.g., time or audience issues). Usually maps to HTTP 401.</li>
 * </ul>
 * <p>
 * Part of the {@code commons.events} base layer (see {@code doc/commons/specification/observability.adoc}).
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public enum EventCategory {
    /**
     * Indicates issues with the token structure, such as malformed tokens,
     * size violations, or decoding failures.
     * <p>
     * This category is typically used for events thrown by NonValidatingJwtParser
     * or TokenHeaderValidator.
     * <p>
     * Usually maps to HTTP 401 Unauthorized.
     */
    INVALID_STRUCTURE,

    /**
     * Indicates issues with the token signature, such as signature verification
     * failures or missing keys.
     * <p>
     * This category is typically used for events thrown by TokenSignatureValidator.
     * <p>
     * Usually maps to HTTP 401 Unauthorized.
     */
    INVALID_SIGNATURE,

    /**
     * Indicates semantic issues with the token, such as expired tokens,
     * audience mismatches, or missing required claims.
     * <p>
     * This category is typically used for events thrown by TokenClaimValidator.
     * <p>
     * Usually maps to HTTP 401 Unauthorized.
     */
    SEMANTIC_ISSUES
}
