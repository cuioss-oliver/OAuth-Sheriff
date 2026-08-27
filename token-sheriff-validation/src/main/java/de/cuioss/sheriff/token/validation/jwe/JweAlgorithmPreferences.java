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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.Collections;
import java.util.List;

/**
 * Manages algorithm preferences for JWE (JSON Web Encryption) decryption per RFC 7516/7518.
 * <p>
 * This class defines which key management algorithms ({@code alg} header) and
 * content encryption algorithms ({@code enc} header) are allowed for JWE token decryption.
 * <p>
 * RSA1_5 is explicitly rejected due to Bleichenbacher attack vulnerability.
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516">RFC 7516 - JSON Web Encryption</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518 - JSON Web Algorithms</a>
 */
@Getter
@EqualsAndHashCode
@ToString
public class JweAlgorithmPreferences {

    /**
     * Explicitly rejected key management algorithms for security reasons.
     * RSA1_5 is vulnerable to Bleichenbacher's chosen-ciphertext attack.
     */
    public static final List<String> REJECTED_KEY_ALGORITHMS = List.of("RSA1_5");

    private final List<String> supportedKeyManagementAlgorithms;
    private final List<String> supportedContentEncryptionAlgorithms;

    /**
     * Default constructor with secure defaults.
     */
    public JweAlgorithmPreferences() {
        this.supportedKeyManagementAlgorithms = getDefaultKeyManagementAlgorithms();
        this.supportedContentEncryptionAlgorithms = getDefaultContentEncryptionAlgorithms();
    }

    /**
     * Constructor with custom algorithm lists.
     *
     * @param supportedKeyManagementAlgorithms   allowed key management algorithms
     * @param supportedContentEncryptionAlgorithms allowed content encryption algorithms
     */
    public JweAlgorithmPreferences(List<String> supportedKeyManagementAlgorithms,
            List<String> supportedContentEncryptionAlgorithms) {
        this.supportedKeyManagementAlgorithms = Collections.unmodifiableList(supportedKeyManagementAlgorithms);
        this.supportedContentEncryptionAlgorithms = Collections.unmodifiableList(supportedContentEncryptionAlgorithms);
    }

    /**
     * @return default supported key management algorithms, in preference order
     * <p>
     * {@code RSA-OAEP-256} (MGF1 with SHA-256) is listed first because it is preferred over
     * {@code RSA-OAEP}, whose OAEP padding uses MGF1 with SHA-1. The SHA-1 variant is retained
     * only for interoperability with issuers that have not yet adopted OAEP-256 (L7); new
     * deployments should prefer {@code RSA-OAEP-256}.
     */
    public static List<String> getDefaultKeyManagementAlgorithms() {
        return List.of("RSA-OAEP-256", "RSA-OAEP", "ECDH-ES");
    }

    /**
     * @return the preferred key management algorithm for new deployments (OAEP with SHA-256
     * rather than the SHA-1 MGF1 variant)
     */
    @SuppressWarnings("java:S3400") // intentional public accessor method; converting to a constant field would break API compatibility
    public static String getPreferredKeyManagementAlgorithm() {
        return "RSA-OAEP-256";
    }

    /**
     * @return default supported content encryption algorithms
     */
    public static List<String> getDefaultContentEncryptionAlgorithms() {
        return List.of("A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512");
    }

    /**
     * Checks if a key management algorithm is supported and not rejected.
     *
     * @param alg the algorithm to check
     * @return true if supported
     */
    public boolean isKeyManagementSupported(String alg) {
        if (alg == null || alg.isEmpty()) {
            return false;
        }
        if (REJECTED_KEY_ALGORITHMS.contains(alg)) {
            return false;
        }
        return supportedKeyManagementAlgorithms.contains(alg);
    }

    /**
     * Checks if a content encryption algorithm is supported.
     *
     * @param enc the algorithm to check
     * @return true if supported
     */
    public boolean isContentEncryptionSupported(String enc) {
        if (enc == null || enc.isEmpty()) {
            return false;
        }
        return supportedContentEncryptionAlgorithms.contains(enc);
    }
}
