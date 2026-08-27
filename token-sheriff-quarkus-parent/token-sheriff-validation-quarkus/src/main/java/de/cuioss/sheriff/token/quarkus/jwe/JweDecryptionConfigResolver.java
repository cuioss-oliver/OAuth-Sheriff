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

import de.cuioss.sheriff.token.quarkus.config.ConfigValueParser;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.validation.jwe.JweAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.tools.logging.CuiLogger;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.*;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * Resolver for creating {@link JweDecryptionConfig} from Quarkus configuration properties.
 * <p>
 * This resolver reads JWE decryption properties and loads private keys using
 * {@link DecryptionKeyLoader}. It supports:
 * <ul>
 *   <li>Single key: via {@code sheriff.token.jwe.decryption-key-path}</li>
 *   <li>Multiple keys: via {@code sheriff.token.jwe.decryption-keys.{kid}.path}</li>
 *   <li>KeyStore: via {@code sheriff.token.jwe.keystore-path}</li>
 * </ul>
 * <p>
 * Returns {@code null} if no JWE properties are configured.
 *
 * @since 1.0
 * @see JwtPropertyKeys.JWE
 */
public class JweDecryptionConfigResolver {

    private static final CuiLogger LOGGER = new CuiLogger(JweDecryptionConfigResolver.class);

    private final Config config;

    public JweDecryptionConfigResolver(Config config) {
        this.config = config;
    }

    /**
     * Resolves JWE decryption configuration from properties.
     *
     * @return the resolved config, or {@code null} if JWE is not configured
     * @throws IllegalStateException if JWE is explicitly configured but key loading fails
     */
    public @Nullable JweDecryptionConfig resolveJweDecryptionConfig() {
        // Check if any JWE property is present
        Optional<String> singleKeyPath = config.getOptionalValue(
                JwtPropertyKeys.JWE.DECRYPTION_KEY_PATH, String.class);
        Optional<String> keystorePath = config.getOptionalValue(
                JwtPropertyKeys.JWE.KEYSTORE_PATH, String.class);

        // Check for multi-key configuration
        Map<String, String> multiKeyPaths = discoverMultiKeyPaths();

        LOGGER.info(INFO.JWE_CONFIG_CHECK, singleKeyPath, keystorePath, multiKeyPaths);

        if (singleKeyPath.isEmpty() && keystorePath.isEmpty() && multiKeyPaths.isEmpty()) {
            LOGGER.info(INFO.JWE_DECRYPTION_NOT_CONFIGURED);
            return null;
        }

        LOGGER.info(INFO.JWE_DECRYPTION_CONFIG_RESOLVING);

        try {
            JweDecryptionConfig.JweDecryptionConfigBuilder builder = JweDecryptionConfig.builder();

            // Load keys from configured source(s)
            if (singleKeyPath.isPresent()) {
                loadSingleKey(builder, singleKeyPath.get());
            }
            if (keystorePath.isPresent()) {
                loadKeystoreKey(builder, keystorePath.get());
            }
            if (!multiKeyPaths.isEmpty()) {
                loadMultipleKeys(builder, multiKeyPaths);
            }

            // Configure algorithm preferences
            configureAlgorithmPreferences(builder);

            // Configure max encrypted token size
            config.getOptionalValue(JwtPropertyKeys.JWE.MAX_ENCRYPTED_TOKEN_SIZE, Integer.class)
                    .ifPresent(builder::maxEncryptedTokenSize);

            JweDecryptionConfig jweConfig = builder.build();
            LOGGER.info(INFO.JWE_DECRYPTION_CONFIG_RESOLVED, jweConfig.getKeyCount());
            return jweConfig;
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new IllegalStateException(
                    "JWE decryption is explicitly configured but key loading failed. "
                            + "Fix the key configuration or remove JWE properties to disable JWE decryption. "
                            + "Cause: " + e.getMessage(), e);
        }
    }

    private void loadSingleKey(JweDecryptionConfig.JweDecryptionConfigBuilder builder, String keyPath) {
        PrivateKey key = DecryptionKeyLoader.loadFromPem(Path.of(keyPath));

        Optional<String> kid = config.getOptionalValue(
                JwtPropertyKeys.JWE.DECRYPTION_KEY_ID, String.class);

        if (kid.isPresent()) {
            builder.decryptionKey(kid.get(), key);
        }
        builder.defaultDecryptionKey(key);
        LOGGER.debug("Loaded single JWE decryption key from: %s", keyPath);
    }

    private void loadKeystoreKey(JweDecryptionConfig.JweDecryptionConfigBuilder builder, String keystorePath) {
        Optional<String> storePassOpt = config.getOptionalValue(
                JwtPropertyKeys.JWE.KEYSTORE_PASSWORD, String.class);
        Optional<String> alias = config.getOptionalValue(
                JwtPropertyKeys.JWE.KEY_ALIAS, String.class);
        Optional<String> keyPassOpt = config.getOptionalValue(
                JwtPropertyKeys.JWE.KEY_PASSWORD, String.class);

        if (alias.isEmpty()) {
            throw new IllegalStateException(
                    ("JWE keystore is configured at '%s' but no key alias is specified. "
                            + "Configure '%s' to select the key entry, or remove '%s' to disable keystore key loading.")
                            .formatted(keystorePath, JwtPropertyKeys.JWE.KEY_ALIAS, JwtPropertyKeys.JWE.KEYSTORE_PATH));
        }

        char[] storePass = storePassOpt.map(String::toCharArray).orElse(new char[0]);
        char[] keyPass = keyPassOpt.map(String::toCharArray).orElse(storePass.clone());

        PrivateKey key = DecryptionKeyLoader.loadFromKeyStore(
                Path.of(keystorePath), storePass, alias.get(), keyPass);

        Optional<String> kid = config.getOptionalValue(
                JwtPropertyKeys.JWE.DECRYPTION_KEY_ID, String.class);
        if (kid.isPresent()) {
            builder.decryptionKey(kid.get(), key);
        }
        builder.defaultDecryptionKey(key);
        LOGGER.debug("Loaded JWE decryption key from keystore: %s, alias: %s", keystorePath, alias.get());
    }

    private void loadMultipleKeys(JweDecryptionConfig.JweDecryptionConfigBuilder builder,
            Map<String, String> keyPaths) {
        Optional<String> defaultKid = config.getOptionalValue(
                JwtPropertyKeys.JWE.DEFAULT_KEY_ID, String.class);

        Map<String, PrivateKey> loadedKeys = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : keyPaths.entrySet()) {
            String kid = entry.getKey();
            String path = entry.getValue();
            PrivateKey key = DecryptionKeyLoader.loadFromPem(Path.of(path));
            builder.decryptionKey(kid, key);
            loadedKeys.put(kid, key);
            LOGGER.debug("Loaded JWE decryption key '%s' from: %s", kid, path);
        }

        // Set default key: use configured default kid, or fall back to the first loaded key
        PrivateKey defaultKey = defaultKid.map(loadedKeys::get)
                .orElseGet(() -> loadedKeys.isEmpty() ? null : loadedKeys.values().iterator().next());
        if (defaultKey != null) {
            builder.defaultDecryptionKey(defaultKey);
        }
    }

    private Map<String, String> discoverMultiKeyPaths() {
        Map<String, String> keyPaths = new LinkedHashMap<>();
        String multiKeyPrefix = JwtPropertyKeys.JWE.MULTI_KEY_PREFIX;

        for (String kid : ConfigValueParser.discoverNameSegments(config, multiKeyPrefix)) {
            config.getOptionalValue(multiKeyPrefix + kid + ".path", String.class)
                    .ifPresent(path -> keyPaths.put(kid, path));
        }
        return keyPaths;
    }

    private void configureAlgorithmPreferences(JweDecryptionConfig.JweDecryptionConfigBuilder builder) {
        Optional<String> keyMgmtAlgs = config.getOptionalValue(
                JwtPropertyKeys.JWE.KEY_MANAGEMENT_ALGORITHMS, String.class);
        Optional<String> contentEncAlgs = config.getOptionalValue(
                JwtPropertyKeys.JWE.CONTENT_ENCRYPTION_ALGORITHMS, String.class);

        if (keyMgmtAlgs.isPresent() || contentEncAlgs.isPresent()) {
            List<String> keyAlgs = keyMgmtAlgs
                    .map(ConfigValueParser::splitCsv)
                    .orElseGet(JweAlgorithmPreferences::getDefaultKeyManagementAlgorithms);
            List<String> encAlgs = contentEncAlgs
                    .map(ConfigValueParser::splitCsv)
                    .orElseGet(JweAlgorithmPreferences::getDefaultContentEncryptionAlgorithms);

            builder.algorithmPreferences(new JweAlgorithmPreferences(keyAlgs, encAlgs));
        }
    }
}
