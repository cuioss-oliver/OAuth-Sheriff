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

import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableGeneratorController
@DisplayName("TokenResponse value object")
class TokenResponseTest {

    @Test
    @DisplayName("Should expose all populated fields through its accessors")
    void shouldExposePopulatedFields() {
        var response = new TokenResponse();
        response.accessToken = "access-token";
        response.tokenType = "Bearer";
        response.expiresIn = 300L;
        response.refreshToken = "refresh-token";
        response.idToken = "id-token";
        response.scope = "openid profile";

        assertAll("token response fields",
                () -> assertEquals("access-token", response.getAccessToken().orElseThrow()),
                () -> assertEquals("Bearer", response.getTokenType().orElseThrow()),
                () -> assertEquals(300L, response.getExpiresIn()),
                () -> assertEquals("refresh-token", response.getRefreshToken().orElseThrow()),
                () -> assertEquals("id-token", response.getIdToken().orElseThrow()),
                () -> assertEquals("openid profile", response.getScope().orElseThrow()));
    }

    @Test
    @DisplayName("Should expose grant-dependent optional fields as empty when absent")
    void shouldExposeAbsentOptionalsAsEmpty() {
        var response = new TokenResponse();
        response.accessToken = "access-token";
        response.tokenType = "Bearer";

        assertAll(
                () -> assertTrue(response.getAccessToken().isPresent()),
                () -> assertEquals(0L, response.getExpiresIn()),
                () -> assertFalse(response.getRefreshToken().isPresent()),
                () -> assertFalse(response.getIdToken().isPresent()),
                () -> assertFalse(response.getScope().isPresent()));
    }

    /**
     * H8: {@code toString()} on the token-carrying value objects must never leak live credential
     * material. A stray render — a log statement, an exception message, or a debugger dump — is the
     * canonical accidental-leak surface, so the secret-bearing fields are asserted absent and the
     * {@code <redacted>} marker asserted present.
     */
    @Nested
    @DisplayName("Secret redaction in toString() (H8)")
    class SecretRedaction {

        @Test
        @DisplayName("Should redact the access, refresh, and ID tokens in StoredToken.toString()")
        void shouldRedactStoredTokenSecrets() {
            String access = Generators.letterStrings(20, 40).next();
            String refresh = Generators.letterStrings(20, 40).next();
            String idToken = Generators.letterStrings(20, 40).next();
            var stored = new StoredToken(access, refresh, idToken, null, null, null);

            String rendered = stored.toString();

            assertAll("redacted StoredToken rendering",
                    () -> assertFalse(rendered.contains(access), "the access token must not appear in toString()"),
                    () -> assertFalse(rendered.contains(refresh), "the refresh token must not appear in toString()"),
                    () -> assertFalse(rendered.contains(idToken), "the ID token must not appear in toString()"),
                    () -> assertTrue(rendered.contains("<redacted>"), "live token material is redacted"));
        }

        @Test
        @DisplayName("Should render the bound subject masked rather than as the plain principal")
        void shouldMaskBoundSubject() {
            String subject = Generators.letterStrings(20, 40).next();
            var stored = new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, null, subject);

            String rendered = stored.toString();

            assertAll("masked subject rendering",
                    () -> assertFalse(rendered.contains(subject),
                            "the bound principal must not appear unmasked in toString()"),
                    () -> assertFalse(rendered.contains("subject=null"),
                            "a present subject is rendered as a mask, not as absent"),
                    () -> assertFalse(rendered.contains("subject=<redacted>"),
                            "the subject is masked into a correlatable hash, not blanket-redacted"));
        }

        @Test
        @DisplayName("Should render absent StoredToken secrets as null rather than a redacted marker")
        void shouldRenderAbsentStoredTokenSecretsAsNull() {
            var stored = new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, null, null);

            String rendered = stored.toString();

            assertAll("absent optional secrets",
                    () -> assertTrue(rendered.contains("refreshToken=null"), "an absent refresh token reads as null"),
                    () -> assertTrue(rendered.contains("idToken=null"), "an absent ID token reads as null"),
                    () -> assertTrue(rendered.contains("subject=null"), "an absent bound subject reads as null"),
                    () -> assertTrue(rendered.contains("accessToken=<redacted>"),
                            "the mandatory access token is always redacted"));
        }

        @Test
        @DisplayName("Should redact the access, refresh, and ID tokens in RotationResult.toString()")
        void shouldRedactRotationResultSecrets() {
            TestTokenHolder holder = TestTokenGenerators.accessTokens().next();
            AccessTokenContent access = holder.asAccessTokenContent();
            String rawAccess = holder.getRawToken();
            String refresh = Generators.letterStrings(20, 40).next();
            String idToken = Generators.letterStrings(20, 40).next();
            var result = new RotationResult(access, refresh, idToken, 300L, true,
                    "openid profile", RotationResult.ScopeDelta.EQUAL);

            String rendered = result.toString();

            assertAll("redacted RotationResult rendering",
                    () -> assertFalse(rendered.contains(rawAccess),
                            "the raw access token must not appear in toString()"),
                    () -> assertFalse(rendered.contains(refresh), "the refresh token must not appear in toString()"),
                    () -> assertFalse(rendered.contains(idToken), "the ID token must not appear in toString()"),
                    () -> assertTrue(rendered.contains("<redacted>"), "live token material is redacted"),
                    () -> assertTrue(rendered.contains("accessTokenExpiresInSeconds=300"),
                            "the non-secret lifetime is shown for diagnostics"),
                    () -> assertTrue(rendered.contains("rotated=true"),
                            "the non-secret rotation flag is shown for diagnostics"));
        }

        @Test
        @DisplayName("Should render an absent RotationResult ID token as null rather than a redacted marker")
        void shouldRenderAbsentRotationIdTokenAsNull() {
            TestTokenHolder holder = TestTokenGenerators.accessTokens().next();
            var result = new RotationResult(holder.asAccessTokenContent(),
                    Generators.letterStrings(20, 40).next(), null, 0L, false,
                    null, RotationResult.ScopeDelta.UNDECLARED);

            String rendered = result.toString();

            assertAll("absent optional ID token",
                    () -> assertTrue(rendered.contains("idToken=null"), "an absent ID token reads as null"),
                    () -> assertTrue(rendered.contains("refreshToken=<redacted>"),
                            "the mandatory refresh token is always redacted"));
        }
    }

    /**
     * M1: RFC 6749 §5.1 makes {@code token_type} REQUIRED, and §5.1 declares its value
     * case-insensitive. A missing or unrecognized {@code token_type} must not be silently consumed
     * as {@code Bearer}, so {@link TokenResponse#hasRecognizedTokenType()} accepts only a
     * case-insensitive {@code Bearer} (RFC 6749) or {@code DPoP} (RFC 9449) and rejects everything
     * else.
     */
    @Nested
    @DisplayName("token_type recognition (M1)")
    class TokenTypeRecognition {

        @Test
        @DisplayName("Should accept Bearer and DPoP case-insensitively")
        void shouldAcceptRecognizedTypes() {
            assertAll("recognized token types",
                    () -> assertTrue(withTokenType("Bearer").hasRecognizedTokenType()),
                    () -> assertTrue(withTokenType("bearer").hasRecognizedTokenType()),
                    () -> assertTrue(withTokenType("BEARER").hasRecognizedTokenType()),
                    () -> assertTrue(withTokenType("DPoP").hasRecognizedTokenType()),
                    () -> assertTrue(withTokenType("dpop").hasRecognizedTokenType()));
        }

        @Test
        @DisplayName("Should reject an absent, blank, or garbage token_type")
        void shouldRejectUnrecognizedTypes() {
            assertAll("unrecognized token types",
                    () -> assertFalse(withTokenType(null).hasRecognizedTokenType(),
                            "an absent token_type must not pass as Bearer"),
                    () -> assertFalse(withTokenType("").hasRecognizedTokenType()),
                    () -> assertFalse(withTokenType("   ").hasRecognizedTokenType()),
                    () -> assertFalse(withTokenType("mac").hasRecognizedTokenType()),
                    () -> assertFalse(withTokenType(Generators.letterStrings(3, 12).next() + "-garbage")
                            .hasRecognizedTokenType()));
        }

        private TokenResponse withTokenType(String tokenType) {
            var response = new TokenResponse();
            response.accessToken = "access-token";
            response.tokenType = tokenType;
            return response;
        }
    }

    /**
     * L11: {@code expires_in} is a primitive {@code long}, so an absent field is indistinguishable
     * from a literal {@code 0}. {@link TokenResponse#getExpiresInSeconds()} normalizes it into a
     * nullable view: a positive, plausible lifetime is present, while an absent ({@code 0}),
     * non-positive, or absurd value is empty so it is neither trusted as a real lifetime nor left to
     * make a token effectively immortal.
     */
    @Nested
    @DisplayName("Nullable lifetime normalization (L11)")
    class LifetimeNormalization {

        @Test
        @DisplayName("Should expose a positive, plausible lifetime as present")
        void shouldExposeKnownLifetime() {
            var response = new TokenResponse();
            response.expiresIn = 300L;

            assertAll("known lifetime",
                    () -> assertTrue(response.getExpiresInSeconds().isPresent()),
                    () -> assertEquals(300L, response.getExpiresInSeconds().orElseThrow()));
        }

        @Test
        @DisplayName("Should treat absent (0), negative, and absurd lifetimes as unknown")
        void shouldTreatAbsentNegativeAndAbsurdAsUnknown() {
            assertAll("unknown lifetimes",
                    () -> assertTrue(withExpiresIn(0L).getExpiresInSeconds().isEmpty(),
                            "an absent expires_in (primitive 0) is unknown"),
                    () -> assertTrue(withExpiresIn(-1L).getExpiresInSeconds().isEmpty(),
                            "a negative expires_in is rejected"),
                    () -> assertTrue(withExpiresIn(Long.MIN_VALUE).getExpiresInSeconds().isEmpty()),
                    () -> assertTrue(withExpiresIn(315_360_001L).getExpiresInSeconds().isEmpty(),
                            "an absurd expires_in beyond the plausible bound is rejected"),
                    () -> assertTrue(withExpiresIn(Long.MAX_VALUE).getExpiresInSeconds().isEmpty()));
        }

        @Test
        @DisplayName("Should accept the maximum plausible lifetime at the boundary")
        void shouldAcceptMaximumPlausibleLifetime() {
            assertEquals(315_360_000L, withExpiresIn(315_360_000L).getExpiresInSeconds().orElseThrow());
        }

        private TokenResponse withExpiresIn(long expiresIn) {
            var response = new TokenResponse();
            response.expiresIn = expiresIn;
            return response;
        }
    }
}
