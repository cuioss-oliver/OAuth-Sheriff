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
package de.cuioss.sheriff.token.quarkus.validation;

import de.cuioss.sheriff.token.validation.pipeline.validator.TokenValidationRule;

/**
 * CDI-discoverable interface for custom token validation rules.
 * <p>
 * Implementations of this interface are automatically discovered by the CDI container
 * and registered in the {@link TokenValidationRuleRegistry}. Discovered rules are
 * executed after all built-in validation steps (signature, claims, expiration, audience,
 * DPoP) and before the token is cached.
 * </p>
 * <p>
 * To create a custom validation rule, implement this interface as an
 * {@code @ApplicationScoped} CDI bean:
 * </p>
 * <pre>
 * &#64;ApplicationScoped
 * public class TenantIdRule implements DiscoverableTokenValidationRule {
 *
 *     &#64;Override
 *     public TokenValidationRule getRule() {
 *         return (token, context) -&gt; {
 *             var tenantId = token.getClaimOption(ClaimName.of("tenant_id"));
 *             if (tenantId.isEmpty()) {
 *                 throw new TokenValidationException(
 *                     SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED,
 *                     "Missing required tenant_id claim"
 *                 );
 *             }
 *         };
 *     }
 * }
 * </pre>
 * <p>
 * Rules are immutable after startup. Runtime registration is not supported.
 * </p>
 *
 * @since 1.0
 * @see TokenValidationRuleRegistry
 * @see TokenValidationRule
 */
public interface DiscoverableTokenValidationRule {

    /**
     * Returns the {@link TokenValidationRule} implementation.
     *
     * @return the validation rule instance, never {@code null}
     */
    TokenValidationRule getRule();

    /**
     * Returns whether this rule is enabled.
     * <p>
     * Disabled rules are not registered in the {@link TokenValidationRuleRegistry}.
     * This allows rules to be conditionally activated via configuration properties.
     * </p>
     *
     * @return {@code true} if this rule is enabled, {@code false} otherwise
     */
    default boolean isEnabled() {
        return true;
    }

    /**
     * Returns the priority of this rule. Rules with lower priority values execute first.
     * <p>
     * The default priority is {@code 1000}. Rules with equal priority execute in
     * CDI discovery order (undefined).
     * </p>
     *
     * @return the priority value, lower means earlier execution
     */
    default int getPriority() {
        return 1000;
    }
}
