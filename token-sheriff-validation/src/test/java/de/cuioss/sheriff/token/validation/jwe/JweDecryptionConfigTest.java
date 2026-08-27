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

import de.cuioss.sheriff.token.validation.test.JweTestTokenFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JweDecryptionConfig Tests")
class JweDecryptionConfigTest {

    @Test
    @DisplayName("Should build with default key")
    void shouldBuildWithDefaultKey() {
        KeyPair kp = JweTestTokenFactory.generateRsaKeyPair();
        var config = JweDecryptionConfig.builder()
                .defaultDecryptionKey(kp.getPrivate())
                .build();

        assertTrue(config.resolveKey(null).isPresent());
        assertTrue(config.resolveKey("unknown").isPresent());
        assertEquals(1, config.getKeyCount());
    }

    @Test
    @DisplayName("Should build with named keys")
    void shouldBuildWithNamedKeys() {
        KeyPair kp1 = JweTestTokenFactory.generateRsaKeyPair();
        KeyPair kp2 = JweTestTokenFactory.generateRsaKeyPair();

        var config = JweDecryptionConfig.builder()
                .decryptionKey("key-1", kp1.getPrivate())
                .decryptionKey("key-2", kp2.getPrivate())
                .build();

        assertTrue(config.resolveKey("key-1").isPresent());
        assertTrue(config.resolveKey("key-2").isPresent());
        assertFalse(config.resolveKey("key-3").isPresent());
        assertFalse(config.resolveKey(null).isPresent());
        assertEquals(2, config.getKeyCount());
    }

    @Test
    @DisplayName("Should resolve kid before falling back to default")
    void shouldResolveKidBeforeDefault() {
        KeyPair kp1 = JweTestTokenFactory.generateRsaKeyPair();
        KeyPair kp2 = JweTestTokenFactory.generateRsaKeyPair();

        var config = JweDecryptionConfig.builder()
                .decryptionKey("key-1", kp1.getPrivate())
                .defaultDecryptionKey(kp2.getPrivate())
                .build();

        assertEquals(kp1.getPrivate(), config.resolveKey("key-1").orElseThrow());
        assertEquals(kp2.getPrivate(), config.resolveKey("unknown").orElseThrow());
        assertEquals(kp2.getPrivate(), config.resolveKey(null).orElseThrow());
    }

    @Test
    @DisplayName("Should throw if no keys configured")
    void shouldThrowIfNoKeys() {
        var builder = JweDecryptionConfig.builder();
        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    @DisplayName("Should have default max encrypted token size")
    void shouldHaveDefaultMaxSize() {
        KeyPair kp = JweTestTokenFactory.generateRsaKeyPair();
        var config = JweDecryptionConfig.builder()
                .defaultDecryptionKey(kp.getPrivate())
                .build();

        assertEquals(32 * 1024, config.getMaxEncryptedTokenSize());
        assertFalse(config.isCompressionEnabled());
    }

    @Test
    @DisplayName("toString should not expose private key material")
    void toStringShouldNotExposeKeyMaterial() {
        KeyPair kp = JweTestTokenFactory.generateRsaKeyPair();
        var config = JweDecryptionConfig.builder()
                .defaultDecryptionKey(kp.getPrivate())
                .build();

        String str = config.toString();
        // Should not contain the actual key class representation (e.g., SunRsaSign RSA private key)
        assertFalse(str.contains("SunRsaSign"), "toString should not contain key implementation details");
        assertFalse(str.contains("private exponent"), "toString should not contain private key exponent");
        // The excluded fields should not appear at all
        assertFalse(str.contains("decryptionKeys="), "toString should not contain decryptionKeys field");
        assertFalse(str.contains("defaultDecryptionKey="), "toString should not contain defaultDecryptionKey field");
    }
}
