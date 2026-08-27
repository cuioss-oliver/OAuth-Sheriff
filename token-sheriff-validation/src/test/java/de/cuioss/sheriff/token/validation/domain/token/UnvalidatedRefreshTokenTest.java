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
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimValueGenerator;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldHandleObjectContracts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link UnvalidatedRefreshToken}.
 */
@EnableGeneratorController
@DisplayName("Tests UnvalidatedRefreshToken functionality")
class UnvalidatedRefreshTokenTest implements ShouldHandleObjectContracts<UnvalidatedRefreshToken> {

    @ParameterizedTest
    @TestTokenSource(value = TokenType.REFRESH_TOKEN, count = 3)
    @DisplayName("Should create UnvalidatedRefreshToken with valid validation")
    void shouldCreateUnvalidatedRefreshTokenWithValidToken(TestTokenHolder tokenHolder) {
        var refreshTokenContent = new UnvalidatedRefreshToken(tokenHolder.getRawToken(), tokenHolder.getClaims());

        assertNotNull(refreshTokenContent, "UnvalidatedRefreshToken should not be null");
        assertEquals(tokenHolder.getRawToken(), refreshTokenContent.getRawToken(), "Raw validation should match");
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");
        assertNotNull(refreshTokenContent.getClaims(), "Claims should not be null");
        assertEquals(tokenHolder.getClaims(), refreshTokenContent.getClaims(), "Claims should match");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.REFRESH_TOKEN, count = 2)
    @DisplayName("Should create UnvalidatedRefreshToken with claims")
    void shouldCreateUnvalidatedRefreshTokenWithClaims(TestTokenHolder tokenHolder) {
        String testValue = "test-value";
        tokenHolder.withClaim("test-claim", ClaimValue.forPlainString(testValue));

        var refreshTokenContent = new UnvalidatedRefreshToken(tokenHolder.getRawToken(), tokenHolder.getClaims());

        assertNotNull(refreshTokenContent, "UnvalidatedRefreshToken should not be null");
        assertEquals(tokenHolder.getRawToken(), refreshTokenContent.getRawToken(), "Raw validation should match");
        assertEquals(TokenType.REFRESH_TOKEN, refreshTokenContent.getTokenType(), "Token type should be REFRESH_TOKEN");
        assertNotNull(refreshTokenContent.getClaims(), "Claims should not be null");
        assertFalse(refreshTokenContent.getClaims().isEmpty(), "Claims should not be empty");
        assertTrue(refreshTokenContent.getClaims().containsKey("test-claim"), "Claims should contain test-claim");
        assertEquals(testValue, refreshTokenContent.getClaims().get("test-claim").getOriginalString(), "Claim value should match");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.REFRESH_TOKEN, count = 2)
    @DisplayName("toString must not leak the raw token or claims")
    void toStringShouldNotLeakCredential(TestTokenHolder tokenHolder) {
        tokenHolder.withClaim("secret-claim", ClaimValue.forPlainString("secret-claim-value"));
        var refreshTokenContent = new UnvalidatedRefreshToken(tokenHolder.getRawToken(), tokenHolder.getClaims());

        String stringRepresentation = refreshTokenContent.toString();

        assertFalse(stringRepresentation.contains(tokenHolder.getRawToken()),
                "toString must not contain the raw refresh token (credential)");
        assertFalse(stringRepresentation.contains("secret-claim-value"),
                "toString must not contain claim values");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.REFRESH_TOKEN, count = 2)
    @DisplayName("Expose claims as immutable map")
    void shouldExposeImmutableClaimsMap(TestTokenHolder tokenHolder) {
        var refreshTokenContent = new UnvalidatedRefreshToken(tokenHolder.getRawToken(), tokenHolder.getClaims());

        var claims = refreshTokenContent.getClaims();
        var claimValue = ClaimValue.forPlainString("injected");
        assertThrows(UnsupportedOperationException.class,
                () -> claims.put("injected", claimValue),
                "Claims map must be unmodifiable");
    }

    @Override
    public UnvalidatedRefreshToken getUnderTest() {
        Map<String, ClaimValue> anyClaims = new HashMap<>();
        for (int i = 0; i < Generators.integers(0, 5).next(); i++) {
            anyClaims.put(Generators.nonEmptyStrings().next(), new ClaimValueGenerator().next());
        }
        return new UnvalidatedRefreshToken(Generators.nonEmptyStrings().next(), anyClaims);
    }
}
