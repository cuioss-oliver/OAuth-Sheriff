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
package de.cuioss.sheriff.token.validation.test;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import lombok.experimental.UtilityClass;

/**
 * Factory for creating JWKS (JSON Web Key Set) content for testing purposes.
 * <p>
 * This class centralizes the creation of JWKS content with support for multiple algorithms.
 * Unlike previous JWKSFactory, this class:
 * <ul>
 *   <li>Supports multiple algorithms (RS256, RS384, RS512)</li>
 *   <li>Creates keys on the fly</li>
 *   <li>Stores keys in static fields instead of the filesystem</li>
 *   <li>Uses standard JDK providers for key material generation</li>
 * </ul>
 * <p>
 * It provides methods to create various types of JWKS content:
 * <ul>
 *   <li>Valid JWKS with a single key for a specific algorithm</li>
 *   <li>Valid JWKS with multiple keys for different algorithms</li>
 *   <li>JWKS with a specific key ID</li>
 *   <li>JWKS with no key ID (default key ID)</li>
 * </ul>
 */
@UtilityClass
public class InMemoryJWKSFactory {

    /**
     * Default key ID used when no key ID is specified.
     */
    public static final String DEFAULT_KEY_ID = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;

    /**
     * Creates a valid JWKS with a single key using the default key for RS256.
     *
     * @return a valid JWKS JSON string
     */
    public static String createDefaultJwks() {
        return InMemoryKeyMaterialHandler.createDefaultJwks();
    }

    /**
     * Creates a valid JWKS with a single key using the default key for the specified algorithm.
     *
     * @param algorithm the algorithm to use
     * @return a valid JWKS JSON string
     */
    public static String createDefaultJwks(InMemoryKeyMaterialHandler.Algorithm algorithm) {
        return InMemoryKeyMaterialHandler.createDefaultJwks(algorithm);
    }

    /**
     * Creates a valid JWKS with a single key using the specified algorithm and key ID.
     *
     * @param algorithm the algorithm to use
     * @param keyId the key ID to use
     * @return a valid JWKS JSON string
     */
    public static String createValidJwksWithKeyId(InMemoryKeyMaterialHandler.Algorithm algorithm, String keyId) {
        return InMemoryKeyMaterialHandler.createJwks(algorithm, keyId);
    }

    /**
     * Creates a valid JWKS with a single key using RS256 and the specified key ID.
     *
     * @param keyId the key ID to use
     * @return a valid JWKS JSON string
     */
    public static String createValidJwksWithKeyId(String keyId) {
        return createValidJwksWithKeyId(InMemoryKeyMaterialHandler.Algorithm.RS256, keyId);
    }

    /**
     * Creates a multi-algorithm JWKS containing keys for all supported algorithms.
     *
     * @return a JWKS JSON string containing keys for all supported algorithms
     */
    public static String createMultiAlgorithmJwks() {
        return InMemoryKeyMaterialHandler.createMultiAlgorithmJwks();
    }

    /**
     * Creates a JwksLoader for the default RS256 key.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader(SecurityEventCounter securityEventCounter) {
        return InMemoryKeyMaterialHandler.createDefaultJwksLoader(securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default key of the specified algorithm.
     *
     * @param algorithm the algorithm
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createJwksLoader(InMemoryKeyMaterialHandler.Algorithm algorithm, SecurityEventCounter securityEventCounter) {
        return InMemoryKeyMaterialHandler.createDefaultJwksLoader(algorithm, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId the key ID
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createJwksLoader(InMemoryKeyMaterialHandler.Algorithm algorithm, String keyId, SecurityEventCounter securityEventCounter) {
        return InMemoryKeyMaterialHandler.createJwksLoader(algorithm, keyId, securityEventCounter);
    }

    /**
     * Creates a JwksLoader containing keys for all supported algorithms.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance with keys for all supported algorithms
     */
    public static JwksLoader createMultiAlgorithmJwksLoader(SecurityEventCounter securityEventCounter) {
        return InMemoryKeyMaterialHandler.createMultiAlgorithmJwksLoader(securityEventCounter);
    }

    /**
     * Creates a JWKS with missing required fields.
     *
     * @param keyId the key ID to use
     * @return a JWKS JSON string with missing required fields
     */
    public static String createJwksWithMissingFields(String keyId) {
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\"}]}".formatted(keyId);
    }

    /**
     * Creates an empty JWKS with no keys.
     *
     * @return an empty JWKS JSON string
     */
    @SuppressWarnings("SameReturnValue")
    public static String createEmptyJwks() {
        return "{\"keys\": []}";
    }

    /**
     * Creates an invalid JSON string that is not a valid JWKS.
     *
     * @return an invalid JSON string
     */
    @SuppressWarnings("SameReturnValue")
    public static String createInvalidJson() {
        return "invalid json";
    }
}