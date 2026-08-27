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

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.jwks.key.JwkKeyHandler;
import de.cuioss.tools.logging.CuiLogger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Core JWE decryption engine using pure JDK crypto (no external libraries).
 * <p>
 * Supports the following algorithm combinations:
 * <ul>
 *   <li>Key Management: RSA-OAEP (SHA-1), RSA-OAEP-256 (SHA-256), ECDH-ES</li>
 *   <li>Content Encryption: A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512</li>
 * </ul>
 * <p>
 * This class is thread-safe and stateless.
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516">RFC 7516 - JSON Web Encryption</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518 - JSON Web Algorithms</a>
 */
public class JweDecryptor {

    private static final CuiLogger LOGGER = new CuiLogger(JweDecryptor.class);
    private static final int MAX_DECOMPRESSED_SIZE = 256 * 1024; // 256KB limit for compression bomb protection

    /**
     * Decrypts a JWE token and returns the inner plaintext (typically a JWS string).
     *
     * @param jweParts the 5 Base64URL-encoded JWE parts
     * @param jweHeader the decoded JWE header
     * @param config the decryption configuration
     * @param counter the security event counter
     * @param dslJson the configured DslJson instance for JSON parsing (with security limits)
     * @return the decrypted plaintext string
     * @throws TokenValidationException if decryption fails
     */
    public String decrypt(String[] jweParts, JwtHeader jweHeader,
            JweDecryptionConfig config, SecurityEventCounter counter,
            DslJson<Object> dslJson) {
        String alg = jweHeader.alg();
        String enc = jweHeader.enc();

        // Validate algorithms
        if (!config.getAlgorithmPreferences().isKeyManagementSupported(alg)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWE_UNSUPPORTED_ALGORITHM, alg, enc);
            counter.increment(SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM,
                    "Unsupported JWE key management algorithm: %s".formatted(alg));
        }
        if (!config.getAlgorithmPreferences().isContentEncryptionSupported(enc)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWE_UNSUPPORTED_ALGORITHM, alg, enc);
            counter.increment(SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM,
                    "Unsupported JWE content encryption algorithm: %s".formatted(enc));
        }

        // Resolve decryption key
        String kid = jweHeader.kid();
        PrivateKey decryptionKey = config.resolveKey(kid)
                .orElseThrow(() -> {
                    LOGGER.warn(JWTValidationLogMessages.WARN.JWE_DECRYPTION_KEY_NOT_FOUND,
                            kid != null ? kid : "<none>");
                    counter.increment(SecurityEventCounter.EventType.JWE_DECRYPTION_KEY_NOT_FOUND);
                    return new TokenValidationException(
                            SecurityEventCounter.EventType.JWE_DECRYPTION_KEY_NOT_FOUND,
                            "No decryption key found for kid: %s".formatted(kid));
                });

        // Validate compression before crypto operations
        var zipOptional = jweHeader.getZip();
        if (zipOptional.isPresent()) {
            String zipAlg = zipOptional.get();
            if (!"DEF".equals(zipAlg)) {
                LOGGER.warn(JWTValidationLogMessages.WARN.JWE_COMPRESSION_NOT_SUPPORTED, zipAlg);
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                        "Unsupported compression algorithm: %s".formatted(zipAlg));
            }
            if (!config.isCompressionEnabled()) {
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                        "JWE compression is disabled");
            }
        }

        try {
            // Decode JWE parts
            byte[] encryptedKey = Base64.getUrlDecoder().decode(jweParts[1]);
            byte[] iv = Base64.getUrlDecoder().decode(jweParts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(jweParts[3]);
            byte[] authTag = Base64.getUrlDecoder().decode(jweParts[4]);

            // AAD is the ASCII bytes of the protected header (first part, before Base64URL decoding)
            byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

            // Decrypt Content Encryption Key (CEK)
            byte[] cek = decryptCek(alg, encryptedKey, decryptionKey, jweHeader, enc, dslJson);

            try {
                // Decrypt content
                byte[] plaintext = decryptContent(enc, cek, iv, ciphertext, authTag, aad);

                // Decompress if zip header was present (already validated above)
                if (zipOptional.isPresent()) {
                    plaintext = decompress(plaintext);
                }

                return new String(plaintext, StandardCharsets.UTF_8);
            } finally {
                // Clear CEK from memory
                Arrays.fill(cek, (byte) 0);
            }
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWE_DECRYPTION_FAILED, e.getMessage());
            counter.increment(SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "JWE decryption failed",
                    e);
        }
    }

    private byte[] decryptCek(String alg, byte[] encryptedKey, PrivateKey key,
            JwtHeader header, String enc, DslJson<Object> dslJson) throws GeneralSecurityException {
        return switch (alg) {
            case "RSA-OAEP" -> decryptCekRsaOaep(encryptedKey, key);
            case "RSA-OAEP-256" -> decryptCekRsaOaep256(encryptedKey, key);
            case "ECDH-ES" -> deriveCekEcdhEs(header, key, enc, dslJson);
            default -> throw new IllegalArgumentException("Unsupported key management algorithm: " + alg);
        };
    }

    private byte[] decryptCekRsaOaep(byte[] encryptedKey, PrivateKey key)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedKey);
    }

    private byte[] decryptCekRsaOaep256(byte[] encryptedKey, PrivateKey key)
            throws GeneralSecurityException {
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, oaepSpec);
        return cipher.doFinal(encryptedKey);
    }

    @SuppressWarnings("java:S3776") // Complexity justified: key agreement requires multiple steps
    private byte[] deriveCekEcdhEs(JwtHeader header, PrivateKey key, String enc,
            DslJson<Object> dslJson) throws GeneralSecurityException {
        // Parse ephemeral public key from header
        String epkJson = header.getEpk().orElseThrow(() ->
                new TokenValidationException(
                        SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                        "ECDH-ES requires epk (ephemeral public key) in JWE header"));

        ECPublicKey ephemeralKey = parseEcPublicKeyFromJwk(epkJson, dslJson);

        // Validate the private key is EC
        if (!(key instanceof ECPrivateKey ecPrivateKey)) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "ECDH-ES requires an EC private key");
        }

        // Validate ephemeral key curve matches private key curve (Invalid Curve Attack prevention)
        ECParameterSpec privateParams = ecPrivateKey.getParams();
        ECParameterSpec ephemeralParams = ephemeralKey.getParams();
        if (!privateParams.getCurve().equals(ephemeralParams.getCurve())
                || !privateParams.getGenerator().equals(ephemeralParams.getGenerator())
                || !privateParams.getOrder().equals(ephemeralParams.getOrder())
                || privateParams.getCofactor() != ephemeralParams.getCofactor()) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Ephemeral key curve does not match private key curve");
        }

        // Independently verify the ephemeral point lies on the curve BEFORE key agreement.
        // Matching curve parameters alone does not prove the supplied point is valid; an
        // off-curve point enables the Invalid Curve Attack. We do not rely on the JCE provider
        // to perform this check (L6).
        validatePointOnCurve(ephemeralKey.getW(), privateParams);

        // Perform ECDH key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(ecPrivateKey);
        keyAgreement.doPhase(ephemeralKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        try {
            // Derive CEK using Concat KDF
            int keyLengthBits = getContentEncryptionKeyLength(enc);
            byte[] apu = header.getApu().map(s -> Base64.getUrlDecoder().decode(s)).orElse(new byte[0]);
            byte[] apv = header.getApv().map(s -> Base64.getUrlDecoder().decode(s)).orElse(new byte[0]);

            return ConcatKdf.derive(sharedSecret, keyLengthBits, enc, apu, apv);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
        }
    }

    /**
     * Independently verifies that an EC point satisfies the curve equation
     * {@code y^2 == x^3 + a*x + b (mod p)} over the prime field of the given parameters,
     * rejecting the point at infinity and coordinates outside {@code [0, p)}.
     * <p>
     * This is a provider-independent Invalid Curve Attack guard: it does not trust the JCE
     * provider to reject an off-curve ephemeral point before ECDH key agreement.
     *
     * @param point  the ephemeral public point to validate
     * @param params the EC domain parameters (curve and prime field)
     */
    private static void validatePointOnCurve(ECPoint point, ECParameterSpec params) {
        if (ECPoint.POINT_INFINITY.equals(point)) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Ephemeral EC point is the point at infinity");
        }
        EllipticCurve curve = params.getCurve();
        if (!(curve.getField() instanceof ECFieldFp fieldFp)) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Ephemeral EC point uses an unsupported (non-prime) field");
        }
        BigInteger p = fieldFp.getP();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Ephemeral EC point coordinates are outside the field range [0, p)");
        }
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).multiply(x)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        if (!lhs.equals(rhs)) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Ephemeral EC point does not lie on the expected curve");
        }
    }

    private byte[] decryptContent(String enc, byte[] cek, byte[] iv, byte[] ciphertext,
            byte[] authTag, byte[] aad) throws GeneralSecurityException {
        return switch (enc) {
            case "A128GCM" -> decryptAesGcm(cek, iv, ciphertext, authTag, aad, 128);
            case "A256GCM" -> decryptAesGcm(cek, iv, ciphertext, authTag, aad, 256);
            case "A128CBC-HS256" -> decryptAesCbcHs(cek, iv, ciphertext, authTag, aad, 16, "HmacSHA256");
            case "A256CBC-HS512" -> decryptAesCbcHs(cek, iv, ciphertext, authTag, aad, 32, "HmacSHA512");
            default -> throw new IllegalArgumentException("Unsupported content encryption: " + enc);
        };
    }

    private byte[] decryptAesGcm(byte[] cek, byte[] iv, byte[] ciphertext, byte[] authTag,
            byte[] aad, int keyBits) throws GeneralSecurityException {
        validateKeyLength(cek, keyBits / 8, "AES-GCM");
        validateIvLength(iv, 12, "AES-GCM");

        // GCM expects ciphertext + authTag concatenated
        byte[] ciphertextWithTag = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
        System.arraycopy(authTag, 0, ciphertextWithTag, ciphertext.length, authTag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), gcmSpec);
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertextWithTag);
    }

    @SuppressWarnings("java:S5542") // CBC+PKCS5Padding required by RFC 7518 Section 5.2.6; padding oracle mitigated by MAC-then-decrypt
    private byte[] decryptAesCbcHs(byte[] cek, byte[] iv, byte[] ciphertext, byte[] authTag,
            byte[] aad, int macKeyLen, String macAlg) throws GeneralSecurityException {
        // Split CEK into MAC key and encryption key per RFC 7518 Section 5.2
        int totalKeyLen = macKeyLen * 2;
        validateKeyLength(cek, totalKeyLen, "AES-CBC-HS");
        validateIvLength(iv, 16, "AES-CBC");

        byte[] macKey = Arrays.copyOfRange(cek, 0, macKeyLen);
        byte[] encKey = Arrays.copyOfRange(cek, macKeyLen, totalKeyLen);

        try {
            // Verify authentication tag (constant-time comparison)
            byte[] computedTag = computeAesCbcHsTag(macKey, macAlg, aad, iv, ciphertext, macKeyLen);
            if (!MessageDigest.isEqual(computedTag, authTag)) {
                throw new SecurityException("Authentication tag verification failed");
            }

            // Decrypt — CBC with PKCS5Padding is required by RFC 7518 Section 5.2.6 for A*CBC-HS*.
            // Padding oracle is mitigated: MAC is verified above before decryption (verify-then-decrypt).
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);
        } finally {
            Arrays.fill(macKey, (byte) 0);
            Arrays.fill(encKey, (byte) 0);
        }
    }

    private byte[] computeAesCbcHsTag(byte[] macKey, String macAlg, byte[] aad, byte[] iv,
            byte[] ciphertext, int macKeyLen) throws GeneralSecurityException {
        // HMAC input per RFC 7518 Section 5.2.2.1: AAD, IV, Ciphertext, AAD-length-in-bits (8 bytes big-endian)
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(macKey, macAlg));
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        // AAD length in bits as 64-bit big-endian
        long aadBitLength = (long) aad.length * 8;
        byte[] al = new byte[8];
        for (int i = 7; i >= 0; i--) {
            al[i] = (byte) (aadBitLength & 0xFF);
            aadBitLength >>= 8;
        }
        mac.update(al);
        byte[] fullTag = mac.doFinal();
        // Truncate to first macKeyLen bytes
        return Arrays.copyOf(fullTag, macKeyLen);
    }

    private byte[] decompress(byte[] data) {
        // RFC 7516 §4.1.3 mandates raw DEFLATE (RFC 1951) without zlib wrapper.
        // No fallback to zlib-wrapped format.
        Inflater inflater = new Inflater(true); // nowrap=true for raw DEFLATE
        inflater.setInput(data);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 2)) {
            byte[] buffer = new byte[4096];
            int totalWritten = 0;
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0 && !inflater.finished()) {
                    throw new TokenValidationException(
                            SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                            "Failed to decompress JWE payload: not valid raw DEFLATE (RFC 1951)");
                }
                totalWritten += count;
                if (totalWritten > MAX_DECOMPRESSED_SIZE) {
                    throw new TokenValidationException(
                            SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                            "Decompressed JWE payload exceeds maximum size limit");
                }
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Failed to decompress JWE payload: %s".formatted(e.getMessage()), e);
        } catch (IOException e) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "IO error during decompression: %s".formatted(e.getMessage()), e);
        } finally {
            inflater.end();
        }
    }

    private static int getContentEncryptionKeyLength(String enc) {
        return switch (enc) {
            case "A128GCM" -> 128;
            case "A256GCM" -> 256;
            case "A128CBC-HS256" -> 256; // 128-bit MAC key + 128-bit enc key
            case "A256CBC-HS512" -> 512; // 256-bit MAC key + 256-bit enc key
            default -> throw new IllegalArgumentException("Unknown enc algorithm: " + enc);
        };
    }

    private static void validateKeyLength(byte[] key, int expectedLen, String context) {
        if (key.length != expectedLen) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "%s: expected key length %d bytes but got %d".formatted(context, expectedLen, key.length));
        }
    }

    private static void validateIvLength(byte[] iv, int expectedLen, String context) {
        if (iv.length != expectedLen) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "%s: expected IV length %d bytes but got %d".formatted(context, expectedLen, iv.length));
        }
    }

    /**
     * Parses an EC public key from an EPK JSON string by deserializing to a {@link JwkKey}
     * and delegating to {@link JwkKeyHandler#parseEcKey(JwkKey)}.
     *
     * @param epkJson the EPK JSON string from the JWE header
     * @param dslJson the configured DslJson instance for JSON parsing
     * @return the parsed EC public key
     * @throws TokenValidationException if parsing fails
     */
    private static ECPublicKey parseEcPublicKeyFromJwk(String epkJson, DslJson<Object> dslJson) {
        try {
            byte[] epkBytes = epkJson.getBytes(StandardCharsets.UTF_8);
            JwkKey jwkKey = dslJson.deserialize(JwkKey.class, epkBytes, epkBytes.length);

            if (jwkKey == null) {
                throw new IllegalArgumentException("EPK JSON parsed to null");
            }

            return (ECPublicKey) JwkKeyHandler.parseEcKey(jwkKey);
        } catch (IOException | InvalidKeySpecException | ClassCastException e) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Failed to parse ephemeral EC public key: %s".formatted(e.getMessage()), e);
        }
    }
}
