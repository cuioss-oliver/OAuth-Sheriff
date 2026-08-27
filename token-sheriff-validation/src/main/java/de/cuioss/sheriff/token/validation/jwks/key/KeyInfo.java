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
package de.cuioss.sheriff.token.validation.jwks.key;

import java.security.PublicKey;

/**
 * Record that holds information about a key, including the key itself and its algorithm.
 * <p>
 * This record is used to store keys along with their algorithm information to support
 * cryptographic agility. The record provides immutability guarantees and value-based
 * equality by default, making it ideal for representing key information.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @param key The public key used for JWT signature verification. This is the cryptographic
 *            key extracted from the JWK that will be used to verify the signature of JWT tokens.
 *            It's typically an RSA or EC public key.
 * @param algorithm The algorithm identifier associated with this key. This field contains
 *                  the algorithm name (e.g., "RS256", "ES384") that should be used with this
 *                  key for signature verification. The algorithm must match the "alg" header
 *                  in the JWT Token for successful verification. Common values include:
 *                  RS256, RS384, RS512, ES256, ES384, ES512.
 * @param keyId The unique identifier for this key. This is the "kid" (Key ID) value from
 *              the JWK, which is used to identify the specific key within a JWKS. When
 *              verifying a JWT Token, the "kid" in the validation header is matched against
 *              this value to select the correct key for signature verification. Key IDs are
 *              particularly important in environments with key rotation, where multiple
 *              valid keys may exist simultaneously.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public record KeyInfo(
PublicKey key,
String algorithm,
String keyId
) {
    /**
     * Creates a new KeyInfo record with validation.
     *
     * @param key the public key used for JWT signature verification
     * @param algorithm the algorithm identifier associated with this key
     * @param keyId the unique identifier for this key
     * @throws IllegalArgumentException if any parameter is null
     */
    public KeyInfo {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId cannot be null");
        }
    }
}
