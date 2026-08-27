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
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenStringValidator}.
 * <p>
 * Tests pre-pipeline token string validation including null, blank, and size checks.
 */
@DisplayName("TokenStringValidator Tests")
@EnableGeneratorController
class TokenStringValidatorTest {

    private TokenStringValidator validator;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        ParserConfig parserConfig = ParserConfig.builder()
                .maxTokenSize(1000)
                .build();
        validator = new TokenStringValidator(parserConfig, securityEventCounter, null);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    @DisplayName("Should throw exception for null, empty, or blank token")
    void shouldThrowExceptionForInvalidToken(String token) {
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY);

        TokenValidationException exception = assertThrows(
                TokenValidationException.class,
                () -> validator.validate(token)
        );

        assertEquals(SecurityEventCounter.EventType.TOKEN_EMPTY, exception.getEventType());
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
    }

    @Test
    @DisplayName("Should throw exception for token exceeding max size")
    void shouldThrowExceptionForTokenExceedingMaxSize() {
        // Create a token larger than maxTokenSize (1000 bytes)
        String largeToken = Generators.letterStrings(1001, 1001).next();

        TokenValidationException exception = assertThrows(
                TokenValidationException.class,
                () -> validator.validate(largeToken)
        );

        assertEquals(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED, exception.getEventType());
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED));
    }

    @Test
    @DisplayName("Should accept valid token within size limit")
    void shouldAcceptValidTokenWithinSizeLimit() {
        String validToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

        assertDoesNotThrow(() -> validator.validate(validToken));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED));
    }

    @Test
    @DisplayName("Should accept token exactly at max size")
    void shouldAcceptTokenExactlyAtMaxSize() {
        // Create a token exactly at maxTokenSize (1000 bytes)
        String tokenAtMaxSize = Generators.letterStrings(1000, 1000).next();

        assertDoesNotThrow(() -> validator.validate(tokenAtMaxSize));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED));
    }

    @Test
    @DisplayName("Should count security events correctly")
    void shouldCountSecurityEventsCorrectly() {
        // Multiple violations should increment counters
        String oversizedToken = Generators.letterStrings(1001, 1001).next();

        assertThrows(TokenValidationException.class, () -> validator.validate(null));
        assertThrows(TokenValidationException.class, () -> validator.validate(""));
        assertThrows(TokenValidationException.class, () -> validator.validate(oversizedToken));

        assertEquals(2, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED));
    }
}
