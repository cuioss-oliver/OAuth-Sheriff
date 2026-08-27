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
package de.cuioss.sheriff.token.validation.jwks;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = {JWKSKeyLoader.class, JwksLoaderFactory.class})
@EnableGeneratorController
@DisplayName("Tests in-memory JWKSKeyLoader functionality")
class InMemoryJwksLoaderTest {

    private JwksLoader inMemoryJwksLoader;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        // Create the InMemoryJwksLoader with the valid content
        inMemoryJwksLoader = JwksLoaderFactory.createInMemoryLoader(InMemoryJWKSFactory.createDefaultJwks());
        inMemoryJwksLoader.initJWKSLoader(securityEventCounter);
    }

    @Test
    @DisplayName("Should load and parse JWKS from string")
    void shouldLoadAndParseJwksFromString() {
        Optional<Key> key = inMemoryJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertTrue(key.isPresent(), "Key should be present for valid kid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Resolving key loader for in-memory JWKS data");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Successfully loaded");
    }

    @Test
    @DisplayName("Should return empty when kid is null")
    void shouldReturnEmptyWhenKidIsNull() {
        Optional<Key> key = inMemoryJwksLoader.getKeyInfo(null).map(KeyInfo::key);
        assertFalse(key.isPresent(), "Key should not be present for null kid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null or empty");
    }

    @Test
    @DisplayName("Should return empty when kid is not found")
    void shouldReturnEmptyWhenKidNotFound() {
        Optional<Key> key = inMemoryJwksLoader.getKeyInfo("unknown-kid").map(KeyInfo::key);
        assertFalse(key.isPresent(), "Key should not be present for unknown kid");
    }

    @Test
    @DisplayName("Should get key with default kid")
    void shouldGetKeyWithDefaultKid() {
        // Test getting a key with the default kid
        Optional<Key> key = inMemoryJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertTrue(key.isPresent(), "Key should be present for default kid");
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    void shouldHandleInvalidJwksFormat() {
        String invalidJwksContent = InMemoryJWKSFactory.createInvalidJson();
        JwksLoader invalidJwksLoader = JwksLoaderFactory.createInMemoryLoader(invalidJwksContent);
        invalidJwksLoader.initJWKSLoader(securityEventCounter);
        Optional<Key> key = invalidJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertFalse(key.isPresent(), "Key should not be present for invalid JWKS");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                JWTValidationLogMessages.ERROR.JWKS_INVALID_JSON.resolveIdentifierString());

    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() {

        String missingFieldsJwksContent = InMemoryJWKSFactory.createJwksWithMissingFields(InMemoryJWKSFactory.DEFAULT_KEY_ID);
        JwksLoader missingFieldsJwksLoader = JwksLoaderFactory.createInMemoryLoader(missingFieldsJwksContent);
        missingFieldsJwksLoader.initJWKSLoader(securityEventCounter);
        Optional<Key> key = missingFieldsJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertFalse(key.isPresent(), "Key should not be present for missing fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
    }

    @Test
    @DisplayName("Should update keys when refreshed with new data")
    void shouldUpdateKeysWhenRefreshedWithNewData() {

        Optional<Key> initialKey = inMemoryJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertTrue(initialKey.isPresent(), "Initial key should be present");

        // When - create a new loader with updated content
        String updatedJwksContent = InMemoryJWKSFactory.createValidJwksWithKeyId("updated-key-id");
        JwksLoader updatedLoader = JwksLoaderFactory.createInMemoryLoader(updatedJwksContent);
        updatedLoader.initJWKSLoader(securityEventCounter);

        // Then - verify the new loader has the updated key
        Optional<Key> oldKey = updatedLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID).map(KeyInfo::key);
        assertFalse(oldKey.isPresent(), "Old key should not be present after update");

        Optional<Key> newKey = updatedLoader.getKeyInfo("updated-key-id").map(KeyInfo::key);
        assertTrue(newKey.isPresent(), "New key should be present after update");
    }

    @Test
    @DisplayName("Should verify default key exists")
    void shouldVerifyDefaultKeyExists() {
        // Verify that the default key is loaded correctly
        Optional<KeyInfo> keyInfo = inMemoryJwksLoader.getKeyInfo(InMemoryJWKSFactory.DEFAULT_KEY_ID);
        assertTrue(keyInfo.isPresent(), "Key info should be present for default key ID");
        assertEquals(InMemoryJWKSFactory.DEFAULT_KEY_ID, keyInfo.get().keyId(), "Key ID should match default");
        assertNotNull(keyInfo.get().key(), "Key should not be null");
    }

}
