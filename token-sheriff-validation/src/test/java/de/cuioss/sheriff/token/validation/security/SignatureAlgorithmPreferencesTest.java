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
package de.cuioss.sheriff.token.validation.security;

import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link SignatureAlgorithmPreferences}.
 * <p>
 * This test class verifies the functionality of the SignatureAlgorithmPreferences class,
 * which implements the requirement <a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.5">VALIDATION-8.5: Cryptographic Agility</a> as specified
 * in the security specification.
 * <p>
 * See: doc/validation/security-reference.adoc
 */
@EnableTestLogger(debug = SignatureAlgorithmPreferences.class, warn = SignatureAlgorithmPreferences.class)
@EnableGeneratorController
@DisplayName("Tests SignatureAlgorithmPreferences")
class SignatureAlgorithmPreferencesTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Initialize with default algorithms")
        void shouldInitializeWithDefaults() {
            var preferences = new SignatureAlgorithmPreferences();
            var expectedDefaults = List.of(
                    "ES512", "ES384", "ES256", "EdDSA", "PS512", "PS384", "PS256", "RS512", "RS384", "RS256");
            assertEquals(expectedDefaults, preferences.getPreferredAlgorithms(),
                    "Default constructor should initialize with default preferred algorithms");
        }

        @Test
        @DisplayName("Initialize with custom algorithms")
        void shouldInitializeWithCustom() {
            var customAlgorithms = List.of("RS256", "ES256");
            var preferences = new SignatureAlgorithmPreferences(customAlgorithms);
            assertEquals(customAlgorithms, preferences.getPreferredAlgorithms(),
                    "Constructor should initialize with custom preferred algorithms");
        }

        @Test
        @DisplayName("Create unmodifiable list")
        void shouldCreateUnmodifiableList() {
            var preferences = new SignatureAlgorithmPreferences(List.of("RS256", "ES256"));
            var preferredAlgorithms = preferences.getPreferredAlgorithms();
            assertThrows(UnsupportedOperationException.class, () -> preferredAlgorithms.add("RS384"),
                    "The preferred algorithms list should be unmodifiable");
        }
    }

    @Nested
    @DisplayName("Default Preferred Algorithms Tests")
    class GetDefaultPreferredAlgorithmsTests {

        @Test
        @DisplayName("Return expected defaults via no-arg constructor")
        void shouldReturnExpectedDefaults() {
            var defaultAlgorithms = new SignatureAlgorithmPreferences().getPreferredAlgorithms();
            assertNotNull(defaultAlgorithms, "Default algorithms should not be null");
            assertFalse(defaultAlgorithms.isEmpty(), "Default algorithms should not be empty");
            var expectedAlgorithms = List.of(
                    "ES512", "ES384", "ES256", "EdDSA", "PS512", "PS384", "PS256", "RS512", "RS384", "RS256");
            assertEquals(expectedAlgorithms, defaultAlgorithms,
                    "Default algorithms should match the expected list");
        }

        // Note: We're not testing logging behavior as it's not critical to functionality
    }

    @Nested
    @DisplayName("isSupported Tests")
    class IsSupportedTests {

        @ParameterizedTest
        @DisplayName("Return true for supported algorithms")
        @ValueSource(strings = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512"})
        void shouldReturnTrueForSupported(String algorithm) {
            var preferences = new SignatureAlgorithmPreferences();
            assertTrue(preferences.isSupported(algorithm), "Algorithm " + algorithm + " should be supported");
        }

        @ParameterizedTest
        @DisplayName("Return false for rejected algorithms")
        @ValueSource(strings = {"HS256", "HS384", "HS512", "none"})
        void shouldReturnFalseForRejected(String algorithm) {
            var preferences = new SignatureAlgorithmPreferences();
            assertFalse(preferences.isSupported(algorithm), "Algorithm " + algorithm + " should be rejected");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.ALGORITHM_REJECTED.resolveIdentifierString());
        }

        @ParameterizedTest
        @DisplayName("Return false for null or empty algorithm")
        @NullAndEmptySource
        void shouldReturnFalseForNullOrEmpty(String algorithm) {
            var preferences = new SignatureAlgorithmPreferences();
            assertFalse(preferences.isSupported(algorithm), "Null or empty algorithm should not be supported");
        }

        @Test
        @DisplayName("Return false for unsupported algorithms")
        void shouldReturnFalseForUnsupported() {
            var preferences = new SignatureAlgorithmPreferences();
            assertFalse(preferences.isSupported("UNSUPPORTED_ALG"), "Unsupported algorithm should return false");
        }

        @Test
        @DisplayName("Respect custom algorithms")
        void shouldRespectCustomAlgorithms() {
            var preferences = new SignatureAlgorithmPreferences(List.of("RS256"));
            assertTrue(preferences.isSupported("RS256"), "RS256 should be supported");
            assertFalse(preferences.isSupported("ES256"), "ES256 should not be supported");
        }
    }

}
