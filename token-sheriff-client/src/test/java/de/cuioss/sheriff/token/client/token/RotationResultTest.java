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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.client.token.RotationResult.ScopeDelta;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Fail-closed construction guards of the {@link RotationResult} compact constructor.
 * <p>
 * A rotation result is what the caller feeds into its refresh-token family, so a result carrying an
 * absent or unusable refresh token would silently poison the next refresh. The compact constructor
 * therefore rejects a {@code null} access token, and a {@code null} or blank refresh token, at
 * construction rather than letting the defect surface later on the wire.
 * <p>
 * The {@code toString()} redaction contract is asserted in
 * {@code TokenResponseTest.SecretRedaction}, which covers both arms of the ID-token ternary across
 * {@code StoredToken} and {@code RotationResult} together; it is deliberately not duplicated here.
 */
@EnableGeneratorController
@DisplayName("RotationResult fail-closed construction guards")
class RotationResultTest {

    private static AccessTokenContent accessToken() {
        return TestTokenGenerators.accessTokens().next().asAccessTokenContent();
    }

    private static String refreshToken() {
        return Generators.letterStrings(20, 40).next();
    }

    @Test
    @DisplayName("Should reject a blank refresh token so a rotation result can never carry an unusable credential")
    void shouldRejectBlankRefreshToken() {
        AccessTokenContent accessToken = accessToken();

        var empty = assertThrows(IllegalArgumentException.class,
                () -> new RotationResult(accessToken, "", null, 300L, false, null, ScopeDelta.UNDECLARED),
                "an empty refresh token must be rejected");
        var whitespace = assertThrows(IllegalArgumentException.class,
                () -> new RotationResult(accessToken, "   ", null, 300L, false, null, ScopeDelta.UNDECLARED),
                "a whitespace-only refresh token must be rejected");

        assertAll("blank refresh token rejection",
                () -> assertEquals("refreshToken must not be blank", empty.getMessage(),
                        "the rejection must name the offending component"),
                () -> assertEquals("refreshToken must not be blank", whitespace.getMessage(),
                        "a whitespace-only token is blank, not merely empty"));
    }

    @Test
    @DisplayName("Should reject a null access token, a null refresh token or a null scope delta")
    void shouldRejectNullComponents() {
        AccessTokenContent accessToken = accessToken();
        String refreshToken = refreshToken();

        var missingScopeDelta = assertThrows(NullPointerException.class,
                () -> new RotationResult(accessToken, refreshToken, null, 300L, false, null, null),
                "a rotation result without a scope reconciliation outcome must be rejected");

        assertAll("mandatory components",
                () -> assertThrows(NullPointerException.class,
                        () -> new RotationResult(null, refreshToken, null, 300L, false, null, ScopeDelta.UNDECLARED),
                        "a rotation result without a validated access token must be rejected"),
                () -> assertThrows(NullPointerException.class,
                        () -> new RotationResult(accessToken, null, null, 300L, false, null, ScopeDelta.UNDECLARED),
                        "a rotation result without a refresh token must be rejected"),
                () -> assertEquals("scopeDelta must not be null", missingScopeDelta.getMessage(),
                        "the rejection must name the offending component"));
    }
}
