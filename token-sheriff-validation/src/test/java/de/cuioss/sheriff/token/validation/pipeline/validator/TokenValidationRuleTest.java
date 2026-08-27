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
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenValidationRule} integration into the validation pipeline.
 */
@EnableTestLogger
@EnableGeneratorController
class TokenValidationRuleTest {

    private IssuerConfig issuerConfig;
    private String validToken;

    @BeforeEach
    void setUp() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        issuerConfig = tokenHolder.getIssuerConfig();
        validToken = tokenHolder.getRawToken();
    }

    @Test
    @DisplayName("Should accept token when no custom rules are configured")
    void shouldAcceptTokenWithNoRules() {
        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .build();

        var result = validator.createAccessToken(AccessTokenRequest.of(validToken));

        assertNotNull(result);
    }

    @Test
    @DisplayName("Should accept token when custom rule passes")
    void shouldAcceptTokenWhenRulePasses() {
        TokenValidationRule passingRule = (token, context) -> {
            // Rule passes by returning normally
        };

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule(passingRule)
                .build();

        var result = validator.createAccessToken(AccessTokenRequest.of(validToken));

        assertNotNull(result);
    }

    @Test
    @DisplayName("Should reject token when custom rule throws TokenValidationException")
    void shouldRejectTokenWhenRuleThrows() {
        TokenValidationRule rejectingRule = (token, context) -> {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED,
                    "Token rejected by custom rule: blocked subject"
            );
        };

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule(rejectingRule)
                .build();

        var request = AccessTokenRequest.of(validToken);
        var exception = assertThrows(TokenValidationException.class,
                () -> validator.createAccessToken(request));

        assertEquals(SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED, exception.getEventType());
        assertTrue(exception.getMessage().contains("blocked subject"));
    }

    @Test
    @DisplayName("Should execute rules in order and stop at first failure")
    void shouldExecuteRulesInOrderAndStopAtFirstFailure() {
        List<String> executionOrder = new ArrayList<>();

        TokenValidationRule firstRule = (token, context) -> executionOrder.add("first");

        TokenValidationRule failingRule = (token, context) -> {
            executionOrder.add("failing");
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED,
                    "Rejected by second rule"
            );
        };

        TokenValidationRule thirdRule = (token, context) -> executionOrder.add("third");

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule(firstRule)
                .tokenValidationRule(failingRule)
                .tokenValidationRule(thirdRule)
                .build();

        var request = AccessTokenRequest.of(validToken);
        assertThrows(TokenValidationException.class,
                () -> validator.createAccessToken(request));

        assertEquals(List.of("first", "failing"), executionOrder,
                "Third rule should not execute after second rule fails");
    }

    @Test
    @DisplayName("Should pass correct token content and context to rule")
    void shouldPassCorrectTokenContentAndContext() {
        TokenValidationRule inspectingRule = (token, context) -> {
            assertNotNull(token, "Token must not be null");
            assertNotNull(token.getIssuer(), "Token must have issuer");
            assertNotNull(context, "Context must not be null");
            assertNotNull(context.getCurrentTime(), "Context must have current time");
        };

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule(inspectingRule)
                .build();

        var result = validator.createAccessToken(AccessTokenRequest.of(validToken));

        assertNotNull(result);
    }

    @Test
    @DisplayName("Should support lambda as functional interface")
    void shouldSupportLambdaAsFunctionalInterface() {
        // Verify TokenValidationRule can be used as a lambda
        TokenValidationRule rule = (token, ctx) -> {
            if (token.getSubject().isEmpty()) {
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.CUSTOM_RULE_REJECTED,
                        "Subject required"
                );
            }
        };

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule(rule)
                .build();

        // Token has a subject, so rule should pass
        var result = validator.createAccessToken(AccessTokenRequest.of(validToken));
        assertNotNull(result);
    }

    @Test
    @DisplayName("Should execute multiple passing rules successfully")
    void shouldExecuteMultiplePassingRules() {
        List<String> executionOrder = new ArrayList<>();

        var validator = TokenValidator.builder()
                .issuerConfig(issuerConfig)
                .tokenValidationRule((token, ctx) -> executionOrder.add("rule1"))
                .tokenValidationRule((token, ctx) -> executionOrder.add("rule2"))
                .tokenValidationRule((token, ctx) -> executionOrder.add("rule3"))
                .build();

        var result = validator.createAccessToken(AccessTokenRequest.of(validToken));

        assertNotNull(result);
        assertEquals(List.of("rule1", "rule2", "rule3"), executionOrder,
                "All rules should execute in insertion order");
    }
}
