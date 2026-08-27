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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link TokenClaimValidator}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.3">VALIDATION-1.3: Signature Validation</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-2.1">VALIDATION-2.1: Base Token Functionality</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-3.1">VALIDATION-3.1: Issuer Configuration</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-3.3">VALIDATION-3.3: Issuer Validation</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.1">VALIDATION-7.1: Log Levels</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.3">VALIDATION-7.3: Security Events</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.4">VALIDATION-8.4: Claims Validation</a></li>
 * </ul>
 * 
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
class TokenClaimValidatorTest {

    private static final SecurityEventCounter SECURITY_EVENT_COUNTER = new SecurityEventCounter();
    private static final ValidationContext VALIDATION_CONTEXT = new ValidationContext(60, null);

    private TokenClaimValidator createValidator(IssuerConfig issuerConfig) {
        return new TokenClaimValidator(issuerConfig, SECURITY_EVENT_COUNTER);
    }

    private IssuerConfig createDefaultIssuerConfig() {
        // Use TestTokenHolder's built-in configuration generation
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        return tokenHolder.getIssuerConfig();
    }

    @Nested
    class ConstructorTests {
        @Test
        @DisplayName("Create validator with all recommended elements")
        void shouldCreateValidatorWithAllRecommendedElements() {
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedAudience(Set.of(TestTokenHolder.TEST_AUDIENCE))
                    .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                    .build();

            TokenClaimValidator validator = createValidator(issuerConfig);

            assertNotNull(validator, "Validator should not be null");
            assertNotNull(validator.getExpectedAudience(), "Expected audience should not be null");
            assertNotNull(validator.getExpectedClientId(), "Expected client ID should not be null");
        }

        @Test
        @DisplayName("No warning when audience validation is explicitly disabled")
        void shouldNotLogWarningWhenAudienceValidationDisabled() {
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                    .audienceValidationDisabled(true)
                    .build();

            TokenClaimValidator validator = createValidator(issuerConfig);

            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");
            // No warning for missing audience when audienceValidationDisabled=true
            assertEquals(initialCount, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT));
        }

        @Test
        @DisplayName("No warning when missing expected client ID (azp is optional per OIDC spec)")
        void shouldNotWarnWhenMissingExpectedClientId() {
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .build();

            TokenClaimValidator validator = createValidator(issuerConfig);

            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");
            // Missing clientId no longer increments security event counter (azp is optional per OIDC spec)
            assertEquals(initialCount, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT),
                    "Missing clientId should not increment security event counter");
        }

        @Test
        @DisplayName("No warning for missing client ID when audience validation is disabled")
        void shouldNotWarnForMissingClientIdWhenAudienceValidationDisabled() {
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();

            TokenClaimValidator validator = createValidator(issuerConfig);

            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");
            // Neither audience nor clientId should increment counter
            assertEquals(initialCount, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT),
                    "Missing clientId should not increment security event counter");
        }
    }

    @Nested
    class MandatoryClaimsValidationTests {
        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
        @DisplayName("Validate token with all mandatory claims")
        void shouldValidateTokenWithAllMandatoryClaims(TestTokenHolder tokenHolder) {
            var validator = createValidator(tokenHolder.getIssuerConfig());

            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder.asAccessTokenContent(), VALIDATION_CONTEXT));

            assertNotNull(result, "Token content should not be null");
        }
    }

    @Nested
    class TokenTypeValidationTests {
        @Test
        @DisplayName("Validate access token type")
        void shouldValidateAccessTokenType() {
            var validator = createValidator(createDefaultIssuerConfig());
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(TestTokenHolder.TEST_CLIENT_ID));

            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder.asAccessTokenContent(), VALIDATION_CONTEXT));

            assertNotNull(result, "Token content should not be null");
            assertEquals(TokenType.ACCESS_TOKEN, result.getTokenType(), "Token type should be ACCESS_TOKEN");
        }

        @Test
        @DisplayName("Validate ID token type")
        void shouldValidateIdTokenType() {
            var validator = createValidator(createDefaultIssuerConfig());
            TestTokenHolder tokenHolder = TestTokenGenerators.idTokens().next();

            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder.asIdTokenContent(), VALIDATION_CONTEXT));

            assertNotNull(result, "Token content should not be null");
            assertEquals(TokenType.ID_TOKEN, result.getTokenType(), "Token type should be ID_TOKEN");
        }
    }
}