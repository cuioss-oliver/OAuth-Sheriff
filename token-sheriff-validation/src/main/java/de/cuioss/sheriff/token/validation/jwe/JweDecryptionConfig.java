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
import org.jspecify.annotations.Nullable;

import java.security.PrivateKey;
import java.util.*;

/**
 * Configuration for JWE (JSON Web Encryption) token decryption per RFC 7516.
 * <p>
 * This class holds the decryption keys and algorithm preferences needed to decrypt
 * JWE tokens. It accepts only {@link PrivateKey} objects — key loading from files,
 * keystores, or other sources is the responsibility of the runtime module (e.g., Quarkus).
 * <p>
 * Decryption keys are configured at the {@link de.cuioss.sheriff.token.validation.TokenValidator}
 * level (not per-issuer) because the private key belongs to this Resource Server,
 * regardless of which Authorization Server encrypted the token.
 * <p>
 * This class is immutable after construction and thread-safe.
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516">RFC 7516 - JSON Web Encryption</a>
 */
@Getter
@ToString
@EqualsAndHashCode(of = "decryptionKeyIds")
public class JweDecryptionConfig {

    /**
     * Default maximum encrypted token size (32KB).
     * JWE tokens are larger than JWS due to encryption overhead.
     */
    public static final int DEFAULT_MAX_ENCRYPTED_TOKEN_SIZE = 32 * 1024;

    @ToString.Exclude
    private final Map<String, PrivateKey> decryptionKeys;

    @ToString.Exclude
    @Nullable
    private final PrivateKey defaultDecryptionKey;

    private final JweAlgorithmPreferences algorithmPreferences;
    private final int maxEncryptedTokenSize;
    private final boolean compressionEnabled;

    /**
     * Set of key IDs used for equals/hashCode (avoids comparing key material).
     */
    private final Set<String> decryptionKeyIds;

    private JweDecryptionConfig(Map<String, PrivateKey> decryptionKeys,
            @Nullable PrivateKey defaultDecryptionKey,
            JweAlgorithmPreferences algorithmPreferences,
            int maxEncryptedTokenSize,
            boolean compressionEnabled) {
        this.decryptionKeys = Collections.unmodifiableMap(decryptionKeys);
        this.defaultDecryptionKey = defaultDecryptionKey;
        this.algorithmPreferences = algorithmPreferences;
        this.maxEncryptedTokenSize = maxEncryptedTokenSize;
        this.compressionEnabled = compressionEnabled;
        this.decryptionKeyIds = this.decryptionKeys.keySet();
    }

    /**
     * Resolves a decryption key by kid from the JWE header.
     * Falls back to the default key if no kid matches or kid is null.
     *
     * @param kid the key ID from the JWE header, may be null
     * @return the matching PrivateKey, or empty if no key found
     */
    public Optional<PrivateKey> resolveKey(@Nullable String kid) {
        if (kid != null && decryptionKeys.containsKey(kid)) {
            return Optional.of(decryptionKeys.get(kid));
        }
        return Optional.ofNullable(defaultDecryptionKey);
    }

    /**
     * @return the total number of configured decryption keys
     */
    public int getKeyCount() {
        int count = decryptionKeys.size();
        if (defaultDecryptionKey != null && !decryptionKeys.containsValue(defaultDecryptionKey)) {
            count++;
        }
        return count;
    }

    /**
     * @return a new builder for JweDecryptionConfig
     */
    public static JweDecryptionConfigBuilder builder() {
        return new JweDecryptionConfigBuilder();
    }

    /**
     * Builder for {@link JweDecryptionConfig}.
     */
    public static class JweDecryptionConfigBuilder {
        private final HashMap<String, PrivateKey> decryptionKeys = new HashMap<>();
        private PrivateKey defaultDecryptionKey;
        private JweAlgorithmPreferences algorithmPreferences = new JweAlgorithmPreferences();
        private int maxEncryptedTokenSize = DEFAULT_MAX_ENCRYPTED_TOKEN_SIZE;
        private boolean compressionEnabled = false;

        /**
         * Adds a decryption key with the given key ID.
         *
         * @param kid the key ID
         * @param key the private decryption key
         * @return this builder
         */
        public JweDecryptionConfigBuilder decryptionKey(String kid, PrivateKey key) {
            this.decryptionKeys.put(kid, key);
            return this;
        }

        /**
         * Sets the default decryption key used when the JWE header has no kid
         * or the kid doesn't match any configured key.
         *
         * @param key the default private decryption key
         * @return this builder
         */
        public JweDecryptionConfigBuilder defaultDecryptionKey(PrivateKey key) {
            this.defaultDecryptionKey = key;
            return this;
        }

        public JweDecryptionConfigBuilder algorithmPreferences(JweAlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        public JweDecryptionConfigBuilder maxEncryptedTokenSize(int maxEncryptedTokenSize) {
            this.maxEncryptedTokenSize = maxEncryptedTokenSize;
            return this;
        }

        public JweDecryptionConfigBuilder compressionEnabled(boolean compressionEnabled) {
            this.compressionEnabled = compressionEnabled;
            return this;
        }

        /**
         * Builds the JweDecryptionConfig.
         *
         * @return a new JweDecryptionConfig instance
         * @throws IllegalArgumentException if no decryption keys are configured
         */
        public JweDecryptionConfig build() {
            if (decryptionKeys.isEmpty() && defaultDecryptionKey == null) {
                throw new IllegalArgumentException("At least one decryption key or a default key must be provided");
            }
            if (maxEncryptedTokenSize <= 0) {
                throw new IllegalArgumentException("maxEncryptedTokenSize must be positive, got: " + maxEncryptedTokenSize);
            }
            return new JweDecryptionConfig(decryptionKeys, defaultDecryptionKey, algorithmPreferences,
                    maxEncryptedTokenSize, compressionEnabled);
        }
    }
}
