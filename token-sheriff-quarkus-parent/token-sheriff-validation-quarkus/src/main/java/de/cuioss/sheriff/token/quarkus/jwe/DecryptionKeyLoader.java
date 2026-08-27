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

import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility for loading private decryption keys from PEM files and keystores.
 * <p>
 * This class handles the operational concern of key loading, which belongs
 * in the Quarkus module rather than the core library. The core library only
 * accepts {@link PrivateKey} objects via
 * {@link de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig}.
 * <p>
 * Supports:
 * <ul>
 *   <li>PKCS#8 PEM files (unencrypted)</li>
 *   <li>JKS and PKCS#12 keystores</li>
 * </ul>
 * <p>
 * Security: Passwords are cleared from {@code char[]} arrays after use.
 *
 * @since 1.0
 */
@UtilityClass
public class DecryptionKeyLoader {

    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    /**
     * Loads a private key from a PKCS#8 PEM file.
     * <p>
     * The PEM file must contain an unencrypted PKCS#8 private key
     * (beginning with {@code -----BEGIN PRIVATE KEY-----}).
     * Supports RSA and EC keys.
     *
     * @param pemFilePath path to the PEM file
     * @return the loaded private key
     * @throws IllegalArgumentException if the file is not a valid PKCS#8 PEM
     * @throws IllegalStateException    if loading fails due to I/O or crypto errors
     */
    public static PrivateKey loadFromPem(Path pemFilePath) {
        try {
            String pemContent = Files.readString(pemFilePath);
            return parsePemContent(pemContent);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read PEM file: " + pemFilePath, e);
        }
    }

    /**
     * Loads a private key from a keystore (JKS or PKCS#12).
     * <p>
     * After loading, the password arrays are cleared for security.
     *
     * @param keystorePath path to the keystore file
     * @param storePass    keystore password (will be cleared after use)
     * @param alias        alias of the key entry
     * @param keyPass      key entry password (will be cleared after use)
     * @return the loaded private key
     * @throws IllegalStateException if loading fails
     */
    public static PrivateKey loadFromKeyStore(Path keystorePath, char[] storePass,
            String alias, char[] keyPass) {
        try (InputStream is = Files.newInputStream(keystorePath)) {
            String type = keystorePath.toString().toLowerCase().endsWith(".p12")
                    || keystorePath.toString().toLowerCase().endsWith(".pfx")
                    ? "PKCS12" : "JKS";

            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(is, storePass);

            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                    alias, new KeyStore.PasswordProtection(keyPass));

            if (entry == null) {
                throw new IllegalArgumentException("No private key entry found for alias: " + alias);
            }
            return entry.getPrivateKey();
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to load key from keystore: " + keystorePath, e);
        } finally {
            Arrays.fill(storePass, '\0');
            Arrays.fill(keyPass, '\0');
        }
    }

    /**
     * Parses a PKCS#8 PEM string into a PrivateKey.
     *
     * @param pemContent the PEM content string
     * @return the parsed private key
     */
    static PrivateKey parsePemContent(String pemContent) {
        if (!pemContent.contains(BEGIN_PRIVATE_KEY)) {
            throw new IllegalArgumentException(
                    "PEM file must contain a PKCS#8 private key (BEGIN PRIVATE KEY). "
                            + "Encrypted keys (BEGIN ENCRYPTED PRIVATE KEY) and PKCS#1 keys "
                            + "(BEGIN RSA PRIVATE KEY) are not supported.");
        }

        String base64 = pemContent
                .replace(BEGIN_PRIVATE_KEY, "")
                .replace(END_PRIVATE_KEY, "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(base64);
        try {
            return parsePrivateKey(new PKCS8EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to parse private key — not RSA or EC", e);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Attempts to parse a private key from a PKCS#8 key spec, trying RSA first then EC.
     *
     * @param keySpec the PKCS#8 encoded key spec
     * @return the parsed private key
     * @throws GeneralSecurityException if the key cannot be parsed as RSA or EC
     */
    private static PrivateKey parsePrivateKey(PKCS8EncodedKeySpec keySpec)
            throws GeneralSecurityException {
        GeneralSecurityException rsaException;
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            rsaException = e;
        }
        try {
            return KeyFactory.getInstance("EC").generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            e.addSuppressed(rsaException);
            throw e;
        }
    }
}
