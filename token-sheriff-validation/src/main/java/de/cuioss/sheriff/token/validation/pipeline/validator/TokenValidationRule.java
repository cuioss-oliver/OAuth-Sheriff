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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;

/**
 * Extension point for custom token validation logic.
 * <p>
 * Implementations are executed after all built-in validation steps (signature, claims,
 * expiration, audience, DPoP) have passed and before the token is stored in the cache.
 * Throwing a {@link TokenValidationException} rejects the token.
 * <p>
 * Custom rules receive the fully validated {@link AccessTokenContent} and the
 * {@link ValidationContext} which provides the current time and clock skew configuration.
 * <p>
 * Example use cases:
 * <ul>
 *   <li>Reject tokens from specific subjects (blocklist)</li>
 *   <li>Require a custom claim (e.g., {@code tenant_id}) to match a request-scoped value</li>
 *   <li>Cross-reference token claims against an external authorization database</li>
 *   <li>Enforce business rules such as maximum token freshness for sensitive endpoints</li>
 * </ul>
 * <p>
 * Rules are immutable after startup. Runtime registration is not supported.
 *
 * @since 1.0
 */
@FunctionalInterface
public interface TokenValidationRule {

    /**
     * Validates the given access token against a custom rule.
     * <p>
     * If the token does not satisfy the rule, the implementation must throw a
     * {@link TokenValidationException} with a clear message and appropriate
     * {@link de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType}.
     * Returning normally indicates the token passed this rule.
     *
     * @param token   the fully validated access token content, never {@code null}
     * @param context the validation context with current time and clock skew, never {@code null}
     * @throws TokenValidationException if the token does not satisfy this rule
     */
    void validate(AccessTokenContent token, ValidationContext context) throws TokenValidationException;
}
