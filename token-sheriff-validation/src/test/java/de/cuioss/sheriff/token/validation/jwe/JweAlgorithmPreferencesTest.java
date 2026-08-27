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
package de.cuioss.sheriff.token.validation.jwe;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JweAlgorithmPreferences Tests")
class JweAlgorithmPreferencesTest {

    @Test
    @DisplayName("Default preferences should include standard algorithms")
    void shouldHaveDefaultAlgorithms() {
        var prefs = new JweAlgorithmPreferences();

        assertTrue(prefs.isKeyManagementSupported("RSA-OAEP"));
        assertTrue(prefs.isKeyManagementSupported("RSA-OAEP-256"));
        assertTrue(prefs.isKeyManagementSupported("ECDH-ES"));

        assertTrue(prefs.isContentEncryptionSupported("A128GCM"));
        assertTrue(prefs.isContentEncryptionSupported("A256GCM"));
        assertTrue(prefs.isContentEncryptionSupported("A128CBC-HS256"));
        assertTrue(prefs.isContentEncryptionSupported("A256CBC-HS512"));
    }

    @Test
    @DisplayName("Should reject RSA1_5 algorithm")
    void shouldRejectRsa15() {
        var prefs = new JweAlgorithmPreferences();
        assertFalse(prefs.isKeyManagementSupported("RSA1_5"));
    }

    @Test
    @DisplayName("Should reject null and empty algorithms")
    void shouldRejectNullAndEmpty() {
        var prefs = new JweAlgorithmPreferences();
        assertFalse(prefs.isKeyManagementSupported(null));
        assertFalse(prefs.isKeyManagementSupported(""));
        assertFalse(prefs.isContentEncryptionSupported(null));
        assertFalse(prefs.isContentEncryptionSupported(""));
    }

    @Test
    @DisplayName("Should support custom algorithm preferences")
    void shouldSupportCustomPreferences() {
        var prefs = new JweAlgorithmPreferences(
                List.of("RSA-OAEP"),
                List.of("A256GCM"));

        assertTrue(prefs.isKeyManagementSupported("RSA-OAEP"));
        assertFalse(prefs.isKeyManagementSupported("RSA-OAEP-256"));
        assertFalse(prefs.isKeyManagementSupported("ECDH-ES"));

        assertTrue(prefs.isContentEncryptionSupported("A256GCM"));
        assertFalse(prefs.isContentEncryptionSupported("A128GCM"));
    }

    @Test
    @DisplayName("RSA1_5 should be rejected even with custom preferences")
    void shouldRejectRsa15EvenWithCustomPrefs() {
        // Even if someone tries to add RSA1_5 to supported list, isKeyManagementSupported
        // checks REJECTED_KEY_ALGORITHMS first
        var prefs = new JweAlgorithmPreferences(
                List.of("RSA1_5", "RSA-OAEP"),
                List.of("A256GCM"));

        assertFalse(prefs.isKeyManagementSupported("RSA1_5"));
        assertTrue(prefs.isKeyManagementSupported("RSA-OAEP"));
    }
}
