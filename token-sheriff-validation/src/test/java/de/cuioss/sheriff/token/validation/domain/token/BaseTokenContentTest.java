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
package de.cuioss.sheriff.token.validation.domain.token;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldHandleObjectContracts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BaseTokenContent}.
 * <p>
 * Uses {@link AccessTokenContent} as the concrete implementation since
 * {@link BaseTokenContent} is sealed and permits only
 * {@link AccessTokenContent} and {@link IdTokenContent}.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests BaseTokenContent functionality")
class BaseTokenContentTest implements ShouldHandleObjectContracts<AccessTokenContent> {

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 3)
    @DisplayName("Create BaseTokenContent with valid parameters")
    void shouldCreateBaseTokenContentWithValidParameters(TestTokenHolder tokenHolder) {
        var content = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertNotNull(content, "BaseTokenContent should not be null");
        assertEquals(tokenHolder.getClaims(), content.getClaims(), "Claims should match");
        assertEquals(tokenHolder.getRawToken(), content.getRawToken(), "Raw token should match");
        assertEquals(TokenType.ACCESS_TOKEN, content.getTokenType(), "Token type should match");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
    @DisplayName("Return claim option correctly")
    void shouldReturnClaimOptionCorrectly(TestTokenHolder tokenHolder) {
        ClaimValue claimValue = ClaimValue.forPlainString("test-value");
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), claimValue);
        var content = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        Optional<ClaimValue> claimOption = content.getClaimOption(ClaimName.ISSUER);

        assertTrue(claimOption.isPresent(), "Claim option should be present");
        assertEquals(claimValue, claimOption.get(), "Claim value should match");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
    @DisplayName("Return empty claim option when claim is not present")
    void shouldReturnEmptyClaimOptionWhenClaimIsNotPresent(TestTokenHolder tokenHolder) {
        tokenHolder.withoutClaim(ClaimName.ISSUER.getName());
        var content = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        Optional<ClaimValue> claimOption = content.getClaimOption(ClaimName.ISSUER);

        assertTrue(claimOption.isEmpty(), "Claim option should be empty");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
    @DisplayName("Expose claims as immutable map")
    void shouldExposeImmutableClaimsMap(TestTokenHolder tokenHolder) {
        var content = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        var claims = content.getClaims();
        var claimValue = ClaimValue.forPlainString("injected");
        assertThrows(UnsupportedOperationException.class,
                () -> claims.put("injected", claimValue),
                "Claims map must be unmodifiable");
        assertThrows(UnsupportedOperationException.class,
                claims::clear,
                "Claims map must be unmodifiable");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
    @DisplayName("Defensively copy the claims map passed to the constructor")
    void shouldDefensivelyCopyClaims(TestTokenHolder tokenHolder) {
        var mutableClaims = new HashMap<>(tokenHolder.getClaims());
        var content = new AccessTokenContent(mutableClaims, tokenHolder.getRawToken());

        mutableClaims.put("added-later", ClaimValue.forPlainString("value"));

        assertFalse(content.getClaims().containsKey("added-later"),
                "Mutating the source map must not affect the token content");
    }

    @Override
    public AccessTokenContent getUnderTest() {
        var tokenHolder = TestTokenGenerators.accessTokens().next();
        return new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());
    }
}
