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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.SortedSet;

import static org.junit.jupiter.api.Assertions.*;

@EnableGeneratorController
@EnableTestLogger
@DisplayName("Tests the TokenType enum functionality")
class TokenTypeTest {

    @ParameterizedTest
    @EnumSource(TokenType.class)
    @DisplayName("Should have mandatory claims defined for each token type")
    void shouldHaveMandatoryClaimsDefined(TokenType tokenType) {
        assertNotNull(tokenType.getMandatoryClaims(), "Mandatory claims should not be null");
    }

    @ParameterizedTest
    @EnumSource(value = TokenType.class, names = {"ACCESS_TOKEN", "ID_TOKEN"})
    @DisplayName("Access and ID tokens should have non-empty mandatory claims")
    void shouldHaveNonEmptyMandatoryClaims(TokenType tokenType) {
        assertFalse(tokenType.getMandatoryClaims().isEmpty(),
                "Mandatory claims should not be empty for " + tokenType);
    }

    @ParameterizedTest
    @EnumSource(TokenType.class)
    @DisplayName("Mandatory claims should be unmodifiable")
    void shouldExposeUnmodifiableMandatoryClaims(TokenType tokenType) {
        SortedSet<ClaimName> mandatoryClaims = tokenType.getMandatoryClaims();

        assertThrows(UnsupportedOperationException.class,
                () -> mandatoryClaims.add(ClaimName.AUDIENCE),
                "Adding to mandatory claims must be rejected for " + tokenType);
        assertThrows(UnsupportedOperationException.class,
                mandatoryClaims::clear,
                "Clearing mandatory claims must be rejected for " + tokenType);
    }
}
