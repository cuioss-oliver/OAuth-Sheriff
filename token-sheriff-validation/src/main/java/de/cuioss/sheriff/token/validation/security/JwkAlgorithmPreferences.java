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

import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Utility class for managing algorithm preferences for JWK (JSON Web Key) parsing.
 * <p>
 * This class validates the 'alg' field in JWK objects during JWKS parsing to ensure
 * only keys with known/supported algorithms are loaded into the key store.
 * This is structural validation, not runtime signature verification preferences.
 * <p>
 * Like {@link SignatureAlgorithmPreferences}, custom algorithm lists reject the insecure
 * symmetric algorithms (HS256, HS384, HS512) and "none" — these can never apply to the
 * asymmetric key material (RSA, EC, OKP) processed from a JWKS.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class JwkAlgorithmPreferences {

    private static final CuiLogger LOGGER = new CuiLogger(JwkAlgorithmPreferences.class);

    /**
     * List of supported JWK algorithms for parsing.
     */
    @Getter
    private final List<String> supportedAlgorithms;

    /**
     * List of explicitly rejected algorithms for security reasons.
     * Mirrors {@link SignatureAlgorithmPreferences}: symmetric MAC algorithms and "none"
     * are never legitimate for asymmetric JWK key material (only RSA, EC, and OKP key
     * types are processed), so rejecting them here cannot break any valid configuration.
     */
    private static final List<String> REJECTED_ALGORITHMS = List.of("HS256", "HS384", "HS512", "none");

    /**
     * Default constructor that initializes the supported algorithms list with default values.
     */
    public JwkAlgorithmPreferences() {
        this.supportedAlgorithms = getDefaultSupportedAlgorithms();
    }

    /**
     * Constructor that allows specifying custom supported algorithms.
     *
     * @param supportedAlgorithms the list of supported algorithms for JWK parsing
     * @throws IllegalArgumentException if the list contains an explicitly rejected
     *                                  algorithm (HS256, HS384, HS512, none)
     */
    public JwkAlgorithmPreferences(List<String> supportedAlgorithms) {
        Objects.requireNonNull(supportedAlgorithms, "supportedAlgorithms must not be null");
        for (String alg : supportedAlgorithms) {
            if (REJECTED_ALGORITHMS.contains(alg)) {
                throw new IllegalArgumentException(
                        "Algorithm '%s' is in the rejected algorithms list and cannot be used as a supported JWK algorithm".formatted(alg));
            }
        }
        this.supportedAlgorithms = Collections.unmodifiableList(supportedAlgorithms);
    }

    /**
     * Gets the default list of supported algorithms for JWK parsing.
     *
     * @return the default list of supported JWK algorithms
     */
    private static List<String> getDefaultSupportedAlgorithms() {
        LOGGER.debug("Getting default supported JWK algorithms");

        // Algorithms that can be parsed and loaded from JWK objects
        // Includes both signature algorithms and JWE key management algorithms
        return List.of("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512",
                "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES");
    }

    /**
     * Checks if an algorithm is supported for JWK parsing.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is supported for JWK parsing, false otherwise
     */
    public boolean isSupported(String algorithm) {
        if (algorithm == null || algorithm.isEmpty()) {
            return false;
        }

        return supportedAlgorithms.contains(algorithm);
    }
}