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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenValidationRule;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link AccessTokenValidationPipeline}'s interaction with custom validation rules,
 * focusing on the cache-hit re-validation contract (M5).
 * <p>
 * Custom validation rules can be stateful (revocation, dynamic policy, rate limiting). They must
 * run on every request — including cache hits — so a token that passed once cannot be served
 * indefinitely after a rule flips to reject it.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("AccessTokenValidationPipeline custom-rule cache-hit tests")
class AccessTokenValidationPipelineTest {

    @Test
    @SuppressWarnings("java:S5778")
    // AccessTokenRequest.of(rawToken) is a pure factory call that never throws
    @DisplayName("Should re-run custom rules on a cache hit and reject a previously-cached token when a rule flips (M5)")
    void shouldReRunCustomRulesOnCacheHit() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        IssuerConfig issuerConfig = tokenHolder.getIssuerConfig();
        String rawToken = tokenHolder.getRawToken();

        FlippingRule flippingRule = new FlippingRule();

        try (TokenValidator validator = TokenValidator.builder()
                     .issuerConfig(issuerConfig)
                     .tokenValidationRule(flippingRule)
                     .cacheConfig(AccessTokenCacheConfig.defaultConfig())
                     .build()) {

            // First validation: cache miss — the rule passes and the token is cached.
            AccessTokenContent first = validator.createAccessToken(AccessTokenRequest.of(rawToken));
            assertNotNull(first, "First validation should succeed and prime the cache");

            // Second validation: cache hit — the rule has flipped to reject, so the cached token
            // must be re-evaluated and rejected rather than served from cache.
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(AccessTokenRequest.of(rawToken)),
                    "A cached token must be rejected once a stateful custom rule flips to reject");
            assertEquals(SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED, exception.getEventType(),
                    "The rejection must originate from the custom rule");
        }

        assertEquals(2, flippingRule.callCount(),
                "The custom rule must run on both the cache-miss and the subsequent cache-hit");
    }

    /**
     * A stateful custom rule that accepts its first invocation and rejects every subsequent one,
     * modelling a rule whose decision changes between requests (e.g. a token revoked after issuance).
     */
    private static final class FlippingRule implements TokenValidationRule {

        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public void validate(AccessTokenContent token, ValidationContext context) {
            if (calls.getAndIncrement() > 0) {
                throw new TokenValidationException(SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED,
                        "Custom rule flipped to reject on re-validation");
            }
        }

        int callCount() {
            return calls.get();
        }
    }
}
