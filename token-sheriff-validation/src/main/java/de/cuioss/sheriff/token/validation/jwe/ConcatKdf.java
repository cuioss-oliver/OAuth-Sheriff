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

import lombok.experimental.UtilityClass;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * NIST Concat KDF (SP 800-56A, Section 5.8.1) for ECDH-ES key derivation per RFC 7518 Section 4.6.
 * <p>
 * The Concat KDF derives a key from a shared secret using:
 * <ul>
 *   <li>The shared secret Z (from ECDH key agreement)</li>
 *   <li>Algorithm ID (the target algorithm, e.g., "A128GCM")</li>
 *   <li>PartyUInfo (apu from JWE header, or empty)</li>
 *   <li>PartyVInfo (apv from JWE header, or empty)</li>
 *   <li>Key data length in bits</li>
 * </ul>
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6">RFC 7518 Section 4.6</a>
 */
@UtilityClass
public class ConcatKdf {

    /**
     * Derives a key using NIST Concat KDF.
     *
     * @param sharedSecret  the shared secret Z from key agreement
     * @param keyLengthBits the desired key length in bits
     * @param algorithmId   the target algorithm identifier (e.g., "A128GCM")
     * @param apu           Agreement PartyUInfo (decoded from Base64URL), may be empty
     * @param apv           Agreement PartyVInfo (decoded from Base64URL), may be empty
     * @return the derived key bytes
     */
    public static byte[] derive(byte[] sharedSecret, int keyLengthBits,
            String algorithmId, byte[] apu, byte[] apv) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            int hashLen = 256; // SHA-256 output length in bits
            int reps = (keyLengthBits + hashLen - 1) / hashLen;

            byte[] algIdBytes = algorithmId.getBytes(StandardCharsets.US_ASCII);

            // Build otherInfo per RFC 7518 Section 4.6.2:
            // AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo (concatenated)
            // Each length-prefixed with 4-byte big-endian length
            byte[] otherInfo = buildOtherInfo(algIdBytes, apu, apv, keyLengthBits);

            byte[] derivedKeyMaterial = new byte[reps * (hashLen / 8)];
            for (int counter = 1; counter <= reps; counter++) {
                digest.reset();
                // roundHash = Hash of: counter, Z, OtherInfo (concatenated)
                digest.update(intToFourBytes(counter));
                digest.update(sharedSecret);
                digest.update(otherInfo);
                byte[] hash = digest.digest();
                System.arraycopy(hash, 0, derivedKeyMaterial, (counter - 1) * hash.length, hash.length);
            }

            // Truncate to desired key length
            int keyLengthBytes = keyLengthBits / 8;
            byte[] result = Arrays.copyOf(derivedKeyMaterial, keyLengthBytes);
            Arrays.fill(derivedKeyMaterial, (byte) 0);
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] buildOtherInfo(byte[] algId, byte[] apu, byte[] apv, int keyLengthBits) {
        // Format: len(algId), algId, len(apu), apu, len(apv), apv, keyLengthBits (each concatenated)
        int totalLen = 4 + algId.length + 4 + apu.length + 4 + apv.length + 4;
        ByteBuffer buffer = ByteBuffer.allocate(totalLen);
        buffer.put(intToFourBytes(algId.length));
        buffer.put(algId);
        buffer.put(intToFourBytes(apu.length));
        buffer.put(apu);
        buffer.put(intToFourBytes(apv.length));
        buffer.put(apv);
        buffer.put(intToFourBytes(keyLengthBits));
        return buffer.array();
    }

    private static byte[] intToFourBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
}
