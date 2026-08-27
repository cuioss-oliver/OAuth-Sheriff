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

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ConcatKdf Tests")
class ConcatKdfTest {

    @Test
    @DisplayName("Should derive key with correct length for A128GCM")
    void shouldDeriveKeyA128Gcm() {
        byte[] sharedSecret = new byte[32];
        for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;

        byte[] derived = ConcatKdf.derive(sharedSecret, 128, "A128GCM", new byte[0], new byte[0]);

        assertNotNull(derived);
        assertEquals(16, derived.length); // 128 bits = 16 bytes
    }

    @Test
    @DisplayName("Should derive key with correct length for A256GCM")
    void shouldDeriveKeyA256Gcm() {
        byte[] sharedSecret = new byte[32];
        for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;

        byte[] derived = ConcatKdf.derive(sharedSecret, 256, "A256GCM", new byte[0], new byte[0]);

        assertNotNull(derived);
        assertEquals(32, derived.length); // 256 bits = 32 bytes
    }

    @Test
    @DisplayName("Should produce different keys for different algorithm IDs")
    void shouldProduceDifferentKeysForDifferentAlgorithms() {
        byte[] sharedSecret = new byte[32];
        for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;

        byte[] key1 = ConcatKdf.derive(sharedSecret, 128, "A128GCM", new byte[0], new byte[0]);
        byte[] key2 = ConcatKdf.derive(sharedSecret, 128, "A256GCM", new byte[0], new byte[0]);

        assertFalse(Arrays.equals(key1, key2));
    }

    @Test
    @DisplayName("Should produce different keys for different apu/apv")
    void shouldProduceDifferentKeysForDifferentPartyInfo() {
        byte[] sharedSecret = new byte[32];
        for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;

        byte[] key1 = ConcatKdf.derive(sharedSecret, 128, "A128GCM", new byte[]{1, 2, 3}, new byte[0]);
        byte[] key2 = ConcatKdf.derive(sharedSecret, 128, "A128GCM", new byte[]{4, 5, 6}, new byte[0]);

        assertFalse(Arrays.equals(key1, key2));
    }

    @Test
    @DisplayName("Should be deterministic")
    void shouldBeDeterministic() {
        byte[] sharedSecret = new byte[32];
        for (int i = 0; i < 32; i++) sharedSecret[i] = (byte) i;

        byte[] key1 = ConcatKdf.derive(sharedSecret, 256, "A256GCM", new byte[]{1}, new byte[]{2});
        byte[] key2 = ConcatKdf.derive(sharedSecret, 256, "A256GCM", new byte[]{1}, new byte[]{2});

        assertArrayEquals(key1, key2);
    }
}
