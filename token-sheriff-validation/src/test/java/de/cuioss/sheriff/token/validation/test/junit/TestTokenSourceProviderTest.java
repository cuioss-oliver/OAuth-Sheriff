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
package de.cuioss.sheriff.token.validation.test.junit;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TestTokenSourceProvider}.
 */
@EnableTestLogger
@DisplayName("TestTokenSourceProvider Tests")
class TestTokenSourceProviderTest {

    @Nested
    @DisplayName("Annotation Usage Tests")
    class AnnotationUsageTests {

        @ParameterizedTest
        @DisplayName("Should demonstrate usage with TestTokenSource annotation")
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        void shouldDemonstrateUsageWithAnnotation(TestTokenHolder tokenHolder) {
            // This test demonstrates that the annotation works correctly
            // The test will be run multiple times with different token holders

            // Verify that the token holder has the correct type
            assertNotNull(tokenHolder, "Token holder should not be null");
            assertEquals(TokenType.ACCESS_TOKEN, tokenHolder.getTokenType(),
                    "Token type should be ACCESS_TOKEN");

            // Verify that the token holder can generate a valid token
            String token = tokenHolder.getRawToken();
            assertNotNull(token, "Token should not be null");
            assertFalse(token.isEmpty(), "Token should not be empty");
        }
    }
}
