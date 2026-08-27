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
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = {JWKSKeyLoader.class, JwksLoaderFactory.class})
@EnableGeneratorController
@DisplayName("Tests file-based JWKSKeyLoader functionality")
class FileJwksLoaderTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @TempDir
    Path tempDir;

    private Path jwksFilePath;
    private JwksLoader fileJwksLoader;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() throws IOException {
        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        // Create a temporary JWKS file for testing
        jwksFilePath = tempDir.resolve("jwks.json");
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        Files.writeString(jwksFilePath, jwksContent);

        // Create the FileJwksLoader with the temporary file
        fileJwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath.toString());
        fileJwksLoader.initJWKSLoader(securityEventCounter);
    }

    @Test
    @DisplayName("Should load and parse JWKS from file")
    void shouldLoadAndParseJwks() {

        Optional<KeyInfo> keyInfo = fileJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present for valid kid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Resolving key loader for JWKS file");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Successfully loaded");
    }

    @Test
    @DisplayName("Should return empty when kid is null")
    void shouldReturnEmptyWhenKidIsNull() {

        Optional<KeyInfo> keyInfo = fileJwksLoader.getKeyInfo(null);
        assertFalse(keyInfo.isPresent(), "Key info should not be present for null kid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null");
    }

    @Test
    @DisplayName("Should return empty when kid is not found")
    void shouldReturnEmptyWhenKidNotFound() {

        Optional<KeyInfo> keyInfo = fileJwksLoader.getKeyInfo("unknown-kid");
        assertFalse(keyInfo.isPresent(), "Key info should not be present for unknown kid");
    }

    @Test
    @DisplayName("Should get key with known kid")
    void shouldGetKeyWithKnownKid() {
        // Test getting a key with the known test kid
        Optional<KeyInfo> keyInfo = fileJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present for known kid");
    }

    @Test
    @DisplayName("Should fail fast for file not found")
    void shouldHandleFileNotFound() {
        // File loading now fails fast at build time
        String nonExistentFile = tempDir.resolve("non-existent.json").toString();
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> JwksLoaderFactory.createFileLoader(nonExistentFile),
                "Should throw IllegalArgumentException for non-existent file");

        assertTrue(exception.getMessage().contains("Cannot read JWKS file"),
                "Exception message should indicate file read failure");
        assertTrue(exception.getMessage().contains(nonExistentFile),
                "Exception message should contain the file name");

        // No cleanup needed
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    void shouldHandleInvalidJwksFormat() throws Exception {
        Path invalidJwksPath = tempDir.resolve("invalid-jwks.json");
        Files.writeString(invalidJwksPath, InMemoryJWKSFactory.createInvalidJson());
        JwksLoader invalidJwksLoader = JwksLoaderFactory.createFileLoader(invalidJwksPath.toString());
        invalidJwksLoader.initJWKSLoader(securityEventCounter);
        Optional<KeyInfo> keyInfo = invalidJwksLoader.getKeyInfo(TEST_KID);
        assertFalse(keyInfo.isPresent(), "Key info should not be present for invalid JWKS");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to parse JWKS JSON");

    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    void shouldHandleMissingRequiredFieldsInJwk() throws Exception {

        Path missingFieldsJwksPath = tempDir.resolve("missing-fields-jwks.json");
        String missingFieldsJwksContent = InMemoryJWKSFactory.createJwksWithMissingFields(TEST_KID);
        Files.writeString(missingFieldsJwksPath, missingFieldsJwksContent);
        JwksLoader missingFieldsJwksLoader = JwksLoaderFactory.createFileLoader(missingFieldsJwksPath.toString());
        missingFieldsJwksLoader.initJWKSLoader(securityEventCounter);
        Optional<KeyInfo> keyInfo = missingFieldsJwksLoader.getKeyInfo(TEST_KID);
        assertFalse(keyInfo.isPresent(), "Key info should not be present for missing fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");

        // No cleanup needed
    }

    @Test
    @DisplayName("Should refresh keys when file is updated")
    void shouldRefreshKeysWhenFileIsUpdated() throws Exception {

        Optional<KeyInfo> initialKeyInfo = fileJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

        // When - update the file with new content
        String updatedJwksContent = InMemoryJWKSFactory.createValidJwksWithKeyId("updated-key-id");
        Files.writeString(jwksFilePath, updatedJwksContent);

        // Create a new FileJwksLoader to force refresh
        JwksLoader newLoader = JwksLoaderFactory.createFileLoader(jwksFilePath.toString());
        newLoader.initJWKSLoader(securityEventCounter);

        // Then - verify the old key is no longer available and the new key is
        Optional<KeyInfo> oldKeyInfo = newLoader.getKeyInfo(TEST_KID);
        assertFalse(oldKeyInfo.isPresent(), "Old key should not be present after update");

        Optional<KeyInfo> newKeyInfo = newLoader.getKeyInfo("updated-key-id");
        assertTrue(newKeyInfo.isPresent(), "New key should be present after update");
    }

    @Test
    @DisplayName("Should verify key exists for test kid")
    void shouldVerifyKeyExistsForTestKid() {
        // Verify that the test key is loaded correctly
        Optional<KeyInfo> keyInfo = fileJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key should be present for test kid");
        assertEquals(TEST_KID, keyInfo.get().keyId(), "Key ID should match test kid");
    }
}
