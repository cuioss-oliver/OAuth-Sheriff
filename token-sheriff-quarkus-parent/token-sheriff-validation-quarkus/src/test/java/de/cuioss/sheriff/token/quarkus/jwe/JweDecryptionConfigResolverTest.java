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
package de.cuioss.sheriff.token.quarkus.jwe;

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JweDecryptionConfigResolver Tests")
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
class JweDecryptionConfigResolverTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Should return null when no JWE properties configured")
    void shouldReturnNullWhenNotConfigured() {
        TestConfig config = new TestConfig(Map.of());
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        assertNull(resolver.resolveJweDecryptionConfig());
    }

    @Test
    @DisplayName("Should load single key from PEM path")
    void shouldLoadSingleKeyFromPem() throws Exception {
        Path pemFile = createRsaPemFile("single-key.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, pemFile.toString());
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_ID, "my-key-1");

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        assertEquals(1, result.getKeyCount());
        assertTrue(result.resolveKey("my-key-1").isPresent());
        assertTrue(result.resolveKey(null).isPresent()); // default key set
    }

    @Test
    @DisplayName("Should load multiple keys for rotation")
    void shouldLoadMultipleKeys() throws Exception {
        Path pemFile1 = createRsaPemFile("key-1.pem");
        Path pemFile2 = createRsaPemFile("key-2.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.MULTI_KEY_PREFIX + "key-1.path", pemFile1.toString());
        props.put(JwtPropertyKeys.JWE.MULTI_KEY_PREFIX + "key-2.path", pemFile2.toString());
        props.put(JwtPropertyKeys.JWE.DEFAULT_KEY_ID, "key-1");

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        assertTrue(result.resolveKey("key-1").isPresent());
        assertTrue(result.resolveKey("key-2").isPresent());
        assertTrue(result.resolveKey(null).isPresent()); // default key set
    }

    @Test
    @DisplayName("Should configure custom algorithm preferences")
    void shouldConfigureAlgorithmPreferences() throws Exception {
        Path pemFile = createRsaPemFile("alg-test.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, pemFile.toString());
        props.put(JwtPropertyKeys.JWE.KEY_MANAGEMENT_ALGORITHMS, "RSA-OAEP");
        props.put(JwtPropertyKeys.JWE.CONTENT_ENCRYPTION_ALGORITHMS, "A256GCM");

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        assertTrue(result.getAlgorithmPreferences().isKeyManagementSupported("RSA-OAEP"));
        assertFalse(result.getAlgorithmPreferences().isKeyManagementSupported("RSA-OAEP-256"));
        assertTrue(result.getAlgorithmPreferences().isContentEncryptionSupported("A256GCM"));
        assertFalse(result.getAlgorithmPreferences().isContentEncryptionSupported("A128GCM"));
    }

    @Test
    @DisplayName("Should configure custom max encrypted token size")
    void shouldConfigureMaxTokenSize() throws Exception {
        Path pemFile = createRsaPemFile("size-test.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, pemFile.toString());
        props.put(JwtPropertyKeys.JWE.MAX_ENCRYPTED_TOKEN_SIZE, "65536");

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        assertEquals(65536, result.getMaxEncryptedTokenSize());
    }

    @Test
    @DisplayName("Should load single key without explicit kid")
    void shouldLoadSingleKeyWithoutKid() throws Exception {
        Path pemFile = createRsaPemFile("no-kid-key.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, pemFile.toString());

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        // Default key should still be set even without explicit kid
        assertTrue(result.resolveKey(null).isPresent());
    }

    @Test
    @DisplayName("Should load multiple keys without explicit default kid")
    void shouldLoadMultipleKeysWithoutDefaultKid() throws Exception {
        Path pemFile1 = createRsaPemFile("multi-1.pem");
        Path pemFile2 = createRsaPemFile("multi-2.pem");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.MULTI_KEY_PREFIX + "first.path", pemFile1.toString());
        props.put(JwtPropertyKeys.JWE.MULTI_KEY_PREFIX + "second.path", pemFile2.toString());

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        JweDecryptionConfig result = resolver.resolveJweDecryptionConfig();

        assertNotNull(result);
        assertTrue(result.resolveKey("first").isPresent());
        assertTrue(result.resolveKey("second").isPresent());
        // First key should be default
        assertTrue(result.resolveKey(null).isPresent());
    }

    @Test
    @DisplayName("Should throw when keystore configured without alias — fail fast naming key-alias")
    void shouldThrowWhenKeystoreAliasMissing() throws Exception {
        Path dummyKeystore = tempDir.resolve("dummy.p12");
        Files.writeString(dummyKeystore, "dummy-content");

        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.KEYSTORE_PATH, dummyKeystore.toString());
        // No KEY_ALIAS configured

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        // Keystore path without key alias must fail fast, mirroring the other
        // key-loading failure paths of this resolver
        var exception = assertThrows(IllegalStateException.class,
                resolver::resolveJweDecryptionConfig);
        assertTrue(exception.getMessage().contains("key loading failed"),
                "Should be wrapped in the fail-closed message: " + exception.getMessage());
        assertTrue(exception.getMessage().contains(JwtPropertyKeys.JWE.KEY_ALIAS),
                "Should name the missing property sheriff.token.jwe.key-alias: " + exception.getMessage());
    }

    @Test
    @DisplayName("Should throw when key loading fails for explicitly configured JWE")
    void shouldThrowWhenKeyLoadingFails() {
        Map<String, String> props = new HashMap<>();
        props.put(JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, "/nonexistent/path/key.pem");

        TestConfig config = new TestConfig(props);
        JweDecryptionConfigResolver resolver = new JweDecryptionConfigResolver(config);

        var exception = assertThrows(IllegalStateException.class,
                resolver::resolveJweDecryptionConfig);
        assertTrue(exception.getMessage().contains("key loading failed"));
    }

    private Path createRsaPemFile(String filename) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        Path pemFile = tempDir.resolve(filename);
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(pemFile, pem);
        return pemFile;
    }
}
