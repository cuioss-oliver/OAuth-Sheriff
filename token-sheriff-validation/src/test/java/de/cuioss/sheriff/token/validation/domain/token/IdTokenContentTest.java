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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link IdTokenContent}.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests IdTokenContent functionality")
class IdTokenContentTest implements ShouldHandleObjectContracts<IdTokenContent> {

    private static final String SAMPLE_TOKEN = TestTokenGenerators.idTokens().next().getRawToken();
    private static final String TEST_NAME = "Test User";
    private static final String TEST_EMAIL = "test@example.com";
    private static final List<String> TEST_AUDIENCE = List.of("client1", "client2");

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ID_TOKEN, count = 3)
    @DisplayName("Create IdTokenContent with valid parameters")
    void shouldCreateIdTokenContentWithValidParameters(TestTokenHolder tokenHolder) {
        var idTokenContent = new IdTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertNotNull(idTokenContent, "IdTokenContent should not be null");
        assertEquals(tokenHolder.getClaims(), idTokenContent.getClaims(), "Claims should match");
        assertEquals(tokenHolder.getRawToken(), idTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ID_TOKEN, count = 2)
    @DisplayName("Return audience correctly when present")
    void shouldReturnAudienceCorrectlyWhenPresent(TestTokenHolder tokenHolder) {
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TEST_AUDIENCE.toString(), TEST_AUDIENCE));
        var idTokenContent = new IdTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        Set<String> audience = idTokenContent.getAudience();

        assertEquals(new LinkedHashSet<>(TEST_AUDIENCE), audience, "Audience should match");
    }

    @Test
    @DisplayName("Throw exception when audience not present")
    void shouldThrowExceptionWhenAudienceNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        assertThrows(IllegalStateException.class, idTokenContent::getAudience,
                "Should throw IllegalStateException for missing audience claim");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ID_TOKEN, count = 2)
    @DisplayName("Return name when present")
    void shouldReturnNameWhenPresent(TestTokenHolder tokenHolder) {
        tokenHolder.withClaim(ClaimName.NAME.getName(), ClaimValue.forPlainString(TEST_NAME));
        var idTokenContent = new IdTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        Optional<String> name = idTokenContent.getDisplayName();

        assertTrue(name.isPresent(), "Name should be present");
        assertEquals(TEST_NAME, name.get(), "Name should match");
    }

    @Test
    @DisplayName("Return empty name when not present")
    void shouldReturnEmptyNameWhenNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> name = idTokenContent.getDisplayName();

        assertTrue(name.isEmpty(), "Name should be empty");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ID_TOKEN, count = 2)
    @DisplayName("Return email when present")
    void shouldReturnEmailWhenPresent(TestTokenHolder tokenHolder) {
        tokenHolder.withClaim(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(TEST_EMAIL));
        var idTokenContent = new IdTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        Optional<String> email = idTokenContent.getEmail();

        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match");
    }

    @Test
    @DisplayName("Return empty email when not present")
    void shouldReturnEmptyEmailWhenNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> email = idTokenContent.getEmail();

        assertTrue(email.isEmpty(), "Email should be empty");
    }

    @Override
    public IdTokenContent getUnderTest() {
        var tokenHolder = TestTokenGenerators.idTokens().next();
        return new IdTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());
    }
}
