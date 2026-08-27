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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JwkAlgorithmPreferences}.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
class JwkAlgorithmPreferencesTest {

    @Test
    void defaultConstructor() {
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();

        assertNotNull(preferences.getSupportedAlgorithms());
        assertFalse(preferences.getSupportedAlgorithms().isEmpty());

        // Verify default algorithms are supported
        assertTrue(preferences.isSupported("RS256"));
        assertTrue(preferences.isSupported("ES256"));
        assertTrue(preferences.isSupported("PS256"));
    }

    @Test
    void customConstructor() {
        List<String> customAlgorithms = List.of("RS256", "ES256");
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences(customAlgorithms);

        assertEquals(customAlgorithms, preferences.getSupportedAlgorithms());
        assertTrue(preferences.isSupported("RS256"));
        assertTrue(preferences.isSupported("ES256"));
        assertFalse(preferences.isSupported("PS256"));
    }

    @Test
    void getDefaultSupportedAlgorithms() {
        List<String> defaultAlgorithms = new JwkAlgorithmPreferences().getSupportedAlgorithms();

        assertNotNull(defaultAlgorithms);
        assertFalse(defaultAlgorithms.isEmpty());

        // Verify expected algorithms are included
        assertTrue(defaultAlgorithms.contains("RS256"));
        assertTrue(defaultAlgorithms.contains("RS384"));
        assertTrue(defaultAlgorithms.contains("RS512"));
        assertTrue(defaultAlgorithms.contains("ES256"));
        assertTrue(defaultAlgorithms.contains("ES384"));
        assertTrue(defaultAlgorithms.contains("ES512"));
        assertTrue(defaultAlgorithms.contains("PS256"));
        assertTrue(defaultAlgorithms.contains("PS384"));
        assertTrue(defaultAlgorithms.contains("PS512"));

        assertTrue(defaultAlgorithms.contains("EdDSA"));

        // JWE key management algorithms
        assertTrue(defaultAlgorithms.contains("RSA-OAEP"));
        assertTrue(defaultAlgorithms.contains("RSA-OAEP-256"));
        assertTrue(defaultAlgorithms.contains("ECDH-ES"));

        // Verify total count
        assertEquals(13, defaultAlgorithms.size());
    }

    @Test
    void isSupportedWithValidAlgorithms() {
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();

        // Test all default supported algorithms
        assertTrue(preferences.isSupported("RS256"));
        assertTrue(preferences.isSupported("RS384"));
        assertTrue(preferences.isSupported("RS512"));
        assertTrue(preferences.isSupported("ES256"));
        assertTrue(preferences.isSupported("ES384"));
        assertTrue(preferences.isSupported("ES512"));
        assertTrue(preferences.isSupported("EdDSA"));
        assertTrue(preferences.isSupported("PS256"));
        assertTrue(preferences.isSupported("PS384"));
        assertTrue(preferences.isSupported("PS512"));
    }

    @Test
    void isSupportedWithInvalidAlgorithms() {
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();

        // Test unsupported algorithms
        assertFalse(preferences.isSupported("HS256"));
        assertFalse(preferences.isSupported("HS384"));
        assertFalse(preferences.isSupported("HS512"));
        assertFalse(preferences.isSupported("none"));
        assertFalse(preferences.isSupported("unknown"));
        assertFalse(preferences.isSupported("invalid"));
    }

    @Test
    void isSupportedWithNullAndEmpty() {
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();

        assertFalse(preferences.isSupported(null));
        assertFalse(preferences.isSupported(""));
    }

    @Test
    void customPreferencesImmutability() {
        List<String> mutableList = List.of("RS256", "ES256");
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences(mutableList);

        List<String> supportedAlgorithms = preferences.getSupportedAlgorithms();

        // Verify the returned list is immutable
        assertThrows(UnsupportedOperationException.class, () ->
                supportedAlgorithms.add("PS256"));
    }

    @Test
    void caseSensitivity() {
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();

        // Algorithms should be case-sensitive
        assertTrue(preferences.isSupported("RS256"));
        assertFalse(preferences.isSupported("rs256"));
        assertFalse(preferences.isSupported("Rs256"));
        assertFalse(preferences.isSupported("RS256 "));
        assertFalse(preferences.isSupported(" RS256"));
    }
}