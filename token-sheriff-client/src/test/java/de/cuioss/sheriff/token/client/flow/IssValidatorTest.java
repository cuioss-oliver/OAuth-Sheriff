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

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("IssValidator RFC 9207 mix-up defence")
class IssValidatorTest {

    private static final String EXPECTED_ISSUER = "https://issuer.example.com/realms/demo";

    private final IssValidator validator = new IssValidator();

    private static CallbackParameters callbackWithIssuer(String issuer) {
        return new CallbackParameters(Generators.nonBlankStrings().next(),
                Generators.nonBlankStrings().next(), null, null, issuer);
    }

    @Nested
    @DisplayName("Accepts")
    class Accepts {

        @Test
        @DisplayName("Should accept a callback whose iss matches the initiating issuer")
        void shouldAcceptMatchingIssuer() {
            var callback = callbackWithIssuer(EXPECTED_ISSUER);

            assertDoesNotThrow(() -> validator.validate(EXPECTED_ISSUER, callback, true));
        }

        @Test
        @DisplayName("Should accept an absent iss when it is not required")
        void shouldAcceptAbsentIssuerWhenNotRequired() {
            var callback = callbackWithIssuer(null);

            assertDoesNotThrow(() -> validator.validate(EXPECTED_ISSUER, callback, false));
        }
    }

    @Nested
    @DisplayName("Rejects")
    class Rejects {

        @Test
        @DisplayName("Should reject a callback whose iss does not match the initiating issuer")
        void shouldRejectMismatchedIssuer() {
            var callback = callbackWithIssuer("https://attacker.example.com/realms/evil");

            assertThrows(ClientProtocolException.class, () -> validator.validate(EXPECTED_ISSUER, callback, false));
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "does not match the initiating issuer");
        }

        @Test
        @DisplayName("Should reject an absent iss when RFC 9207 iss is required")
        void shouldRejectAbsentIssuerWhenRequired() {
            var callback = callbackWithIssuer(null);

            assertThrows(ClientProtocolException.class, () -> validator.validate(EXPECTED_ISSUER, callback, true));
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "<absent>");
        }

        @Test
        @DisplayName("Should reject an iss that differs only in trailing length")
        void shouldRejectLengthMismatch() {
            var callback = callbackWithIssuer(EXPECTED_ISSUER + "/extra");

            assertThrows(ClientProtocolException.class, () -> validator.validate(EXPECTED_ISSUER, callback, false));
        }

        @Test
        @DisplayName("Should reject null arguments")
        void shouldRejectNullArguments() {
            var callback = callbackWithIssuer(EXPECTED_ISSUER);

            assertAll("null-guards",
                    () -> assertThrows(NullPointerException.class, () -> validator.validate(null, callback, false)),
                    () -> assertThrows(NullPointerException.class,
                            () -> validator.validate(EXPECTED_ISSUER, null, false)));
        }
    }
}
