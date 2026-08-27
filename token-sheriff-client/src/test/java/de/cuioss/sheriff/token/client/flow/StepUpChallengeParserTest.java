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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser.StepUpChallenge;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the RFC 9110 {@code auth-param} grammar {@link StepUpChallengeParser} implements when it
 * reads an RFC 9470 step-up challenge off a {@code WWW-Authenticate} header: top-level comma
 * splitting that respects quoted-strings, backslash unescaping inside a {@code quoted-string},
 * unquoted {@code token} values, and the fail-safe handling of malformed segments.
 * <p>
 * The header literals are deliberately hand-written rather than generated — the grammar under test is
 * about the exact placement of quotes, commas and backslashes, so the structural characters are the
 * specification. Only the semantically free {@code acr} token values are generated.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("StepUpChallengeParser auth-param grammar")
class StepUpChallengeParserTest {

    private static final String CHALLENGE_PREFIX = "Bearer error=\"insufficient_user_authentication\"";

    private final StepUpChallengeParser parser = new StepUpChallengeParser();

    private static String acrToken() {
        return "urn:acr:" + Generators.letterStrings(3, 10).next();
    }

    private StepUpChallenge parseRequired(String header) {
        Optional<StepUpChallenge> challenge = parser.parse(header);
        assertTrue(challenge.isPresent(), "header must yield an actionable challenge: " + header);
        return challenge.get();
    }

    @Nested
    @DisplayName("Quoted-string values")
    class QuotedStringValues {

        @Test
        @DisplayName("Should keep a comma inside a quoted acr_values with its own parameter rather than splitting on it")
        void shouldNotSplitOnCommaInsideQuotes() {
            var first = acrToken();
            var second = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"" + first + "," + second + "\"";

            var challenge = parseRequired(header);

            assertEquals(Optional.of(first + "," + second), challenge.getAcrValues(),
                    "a comma inside the quoted-string belongs to the value, not to the auth-param list");
        }

        @Test
        @DisplayName("Should unescape a backslash-escaped quote inside a quoted acr_values (RFC 9110 §5.6.4)")
        void shouldUnescapeEscapedQuote() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"\\\"" + acr + "\\\"\"";

            var challenge = parseRequired(header);

            assertEquals(Optional.of("\"" + acr + "\""), challenge.getAcrValues(),
                    "an escaped quote must be unescaped into the value and must not close the quoted-string");
        }

        @Test
        @DisplayName("Should unescape a backslash-escaped backslash inside a quoted acr_values")
        void shouldUnescapeEscapedBackslash() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"" + acr + "\\\\\"";

            var challenge = parseRequired(header);

            assertEquals(Optional.of(acr + "\\"), challenge.getAcrValues(),
                    "a doubled backslash must collapse to a single literal backslash");
        }

        @Test
        @DisplayName("Should leave an unterminated quoted acr_values verbatim instead of stripping a lone quote")
        void shouldLeaveUnterminatedQuoteVerbatim() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"" + acr;

            var challenge = parseRequired(header);

            assertEquals(Optional.of("\"" + acr), challenge.getAcrValues(),
                    "a value that never closes its quote is not a quoted-string and stays verbatim");
        }
    }

    @Nested
    @DisplayName("Unquoted token values and malformed segments")
    class UnquotedAndMalformed {

        @Test
        @DisplayName("Should accept unquoted token values for both acr_values and max_age")
        void shouldAcceptUnquotedTokenValues() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=" + acr + ", max_age=5";

            var challenge = parseRequired(header);

            assertAll("unquoted auth-param values",
                    () -> assertEquals(Optional.of(acr), challenge.getAcrValues(),
                            "an unquoted token value is taken as-is"),
                    () -> assertEquals(Optional.of(5), challenge.getMaxAge(),
                            "a single-character max_age is too short to be a quoted-string and stays verbatim"));
        }

        @Test
        @DisplayName("Should not treat a backslash outside a quoted-string as an escape")
        void shouldNotEscapeOutsideQuotes() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=" + acr + "\\, max_age=60";

            var challenge = parseRequired(header);

            assertAll("backslash outside quotes",
                    () -> assertEquals(Optional.of(acr + "\\"), challenge.getAcrValues(),
                            "the trailing backslash stays in the value and does not swallow the separator"),
                    () -> assertEquals(Optional.of(60), challenge.getMaxAge(),
                            "the comma after an unquoted backslash still separates the next auth-param"));
        }

        @Test
        @DisplayName("Should skip a segment carrying no '=' rather than rejecting the whole challenge")
        void shouldSkipSegmentWithoutEquals() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"" + acr + "\", realm";

            var challenge = parseRequired(header);

            assertEquals(Optional.of(acr), challenge.getAcrValues(),
                    "a valueless segment is ignored and the well-formed parameters still apply");
        }

        @Test
        @DisplayName("Should skip a segment whose name is empty rather than binding an empty auth-param name")
        void shouldSkipSegmentWithEmptyName() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", =orphan, acr_values=\"" + acr + "\"";

            var challenge = parseRequired(header);

            assertEquals(Optional.of(acr), challenge.getAcrValues(),
                    "a segment starting with '=' carries no auth-param name and is ignored");
        }
    }

    @Nested
    @DisplayName("max_age handling")
    class MaxAgeHandling {

        @Test
        @DisplayName("Should drop an empty quoted max_age while keeping the acr_values constraint")
        void shouldDropEmptyMaxAge() {
            var acr = acrToken();
            String header = CHALLENGE_PREFIX + ", acr_values=\"" + acr + "\", max_age=\"\"";

            var challenge = parseRequired(header);

            assertAll("empty max_age",
                    () -> assertTrue(challenge.getMaxAge().isEmpty(),
                            "an empty max_age constrains nothing and is dropped"),
                    () -> assertEquals(Optional.of(acr), challenge.getAcrValues(),
                            "dropping max_age must not discard the acr_values constraint"));
        }

        @Test
        @DisplayName("Should ignore a challenge whose only constraint is an empty max_age")
        void shouldIgnoreChallengeWithOnlyEmptyMaxAge() {
            String header = CHALLENGE_PREFIX + ", max_age=\"  \"";

            assertTrue(parser.parse(header).isEmpty(),
                    "a challenge left with no constraint at all is not actionable");
        }

        @Test
        @DisplayName("Should ignore a challenge whose only constraint is a blank acr_values (H1)")
        void shouldIgnoreChallengeWithOnlyBlankAcrValues() {
            String header = CHALLENGE_PREFIX + ", acr_values=\"   \"";

            assertTrue(parser.parse(header).isEmpty(),
                    "a blank acr_values names no value, so the challenge constrains nothing and must not "
                            + "be actionable — an actionable-but-unverifiable challenge is the fail-open "
                            + "shape H1 forbids");
        }

        @Test
        @DisplayName("Should drop a blank acr_values while keeping the max_age constraint")
        void shouldDropBlankAcrValuesKeepingMaxAge() {
            String header = CHALLENGE_PREFIX + ", acr_values=\"  \", max_age=\"300\"";

            var challenge = parseRequired(header);

            assertAll("blank acr_values",
                    () -> assertTrue(challenge.getAcrValues().isEmpty(),
                            "a blank acr_values constrains nothing and is dropped"),
                    () -> assertEquals(Optional.of(300), challenge.getMaxAge(),
                            "dropping acr_values must not discard the max_age constraint"));
        }
    }
}
