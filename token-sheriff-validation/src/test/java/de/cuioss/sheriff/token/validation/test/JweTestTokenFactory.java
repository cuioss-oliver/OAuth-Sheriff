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

import io.jsonwebtoken.Jwts;
import lombok.experimental.UtilityClass;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.*;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.*;
import java.util.zip.Deflater;

/**
 * Factory for creating JWE test tokens using JJWT for JWS creation and JDK crypto for JWE wrapping.
 */
@UtilityClass
public class JweTestTokenFactory {

    /**
     * Creates a JWE token wrapping a signed JWS access token.
     *
     * @param signingKey    the private key to sign the inner JWS
     * @param encryptionKey the public key to encrypt the JWE (RSA)
     * @param sigAlg        the JWS signature algorithm name (e.g., "RS256")
     * @param jweAlg        the JWE key management algorithm (e.g., "RSA-OAEP")
     * @param jweEnc        the JWE content encryption algorithm (e.g., "A256GCM")
     * @param issuer        the issuer claim
     * @param kid           the key ID for the JWE header (may be null)
     * @return the JWE compact serialization string
     */
    public static String createJweWrappedAccessToken(PrivateKey signingKey, PublicKey encryptionKey,
            String sigAlg, String jweAlg, String jweEnc, String issuer, String kid) {
        // Create inner JWS
        String innerJws = createSignedJws(signingKey, sigAlg, issuer);
        // Encrypt as JWE
        return encryptAsJwe(innerJws, encryptionKey, jweAlg, jweEnc, kid);
    }

    /**
     * Creates a signed JWS access token using JJWT.
     */
    public static String createSignedJws(PrivateKey signingKey, String sigAlg, String issuer) {
        var sigAlgorithm = switch (sigAlg) {
            case "RS256" -> Jwts.SIG.RS256;
            case "RS384" -> Jwts.SIG.RS384;
            case "RS512" -> Jwts.SIG.RS512;
            case "ES256" -> Jwts.SIG.ES256;
            case "ES384" -> Jwts.SIG.ES384;
            default -> Jwts.SIG.RS256;
        };

        return Jwts.builder()
                .header().keyId(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID).and()
                .issuer(issuer)
                .subject("test-subject")
                .audience().add("test-audience").and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .claim("scope", "openid profile")
                .signWith(signingKey, sigAlgorithm)
                .compact();
    }

    /**
     * Encrypts a plaintext (inner JWS) as a JWE compact serialization.
     */
    public static String encryptAsJwe(String plaintext, PublicKey encryptionKey,
            String alg, String enc, String kid) {
        try {
            // Build JWE protected header
            Map<String, String> headerMap = new LinkedHashMap<>();
            headerMap.put("alg", alg);
            headerMap.put("enc", enc);
            if (kid != null) {
                headerMap.put("kid", kid);
            }
            String headerJson = buildJson(headerMap);
            String encodedHeader = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));

            // Generate CEK
            int cekBits = getCekBits(enc);
            byte[] cek = new byte[cekBits / 8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(cek);

            // Encrypt CEK with public key
            byte[] encryptedKey = encryptCek(cek, encryptionKey, alg);

            // Generate IV
            int ivLen = enc.contains("GCM") ? 12 : 16;
            byte[] iv = new byte[ivLen];
            random.nextBytes(iv);

            // AAD = ASCII(encodedHeader)
            byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // Encrypt content
            byte[] ciphertext;
            byte[] authTag;

            if (enc.contains("GCM")) {
                byte[] result = encryptAesGcm(cek, iv, plaintextBytes, aad);
                // Last 16 bytes are the auth tag
                ciphertext = Arrays.copyOfRange(result, 0, result.length - 16);
                authTag = Arrays.copyOfRange(result, result.length - 16, result.length);
            } else {
                // AES-CBC-HS
                int macKeyLen = cek.length / 2;
                byte[] macKey = Arrays.copyOfRange(cek, 0, macKeyLen);
                byte[] encKey = Arrays.copyOfRange(cek, macKeyLen, cek.length);
                ciphertext = encryptAesCbc(encKey, iv, plaintextBytes);
                authTag = computeAesCbcHsTag(macKey, getMacAlg(enc), aad, iv, ciphertext, macKeyLen);
            }

            // Build compact serialization
            return encodedHeader + "." +
                    base64Url(encryptedKey) + "." +
                    base64Url(iv) + "." +
                    base64Url(ciphertext) + "." +
                    base64Url(authTag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create JWE test token", e);
        }
    }

    /**
     * Generates an RSA key pair for JWE encryption/decryption testing.
     */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }

    /**
     * Generates an EC key pair for ECDH-ES testing.
     */
    public static KeyPair generateEcKeyPair(String curve) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec(curve));
            return keyGen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("EC key generation failed", e);
        }
    }

    /**
     * Creates a JWE token with tampered auth tag for security testing.
     */
    public static String createJweWithTamperedAuthTag(PrivateKey signingKey, PublicKey encryptionKey,
            String issuer) {
        String jwe = createJweWrappedAccessToken(signingKey, encryptionKey,
                "RS256", "RSA-OAEP", "A256GCM", issuer, null);
        String[] parts = jwe.split("\\.");
        // Tamper with auth tag (last part)
        byte[] authTag = Base64.getUrlDecoder().decode(parts[4]);
        authTag[0] ^= 0xFF;
        parts[4] = base64Url(authTag);
        return String.join(".", parts);
    }

    /**
     * Creates a JWE token with tampered ciphertext for security testing.
     */
    public static String createJweWithTamperedCiphertext(PrivateKey signingKey, PublicKey encryptionKey,
            String issuer) {
        String jwe = createJweWrappedAccessToken(signingKey, encryptionKey,
                "RS256", "RSA-OAEP", "A256GCM", issuer, null);
        String[] parts = jwe.split("\\.");
        // Tamper with ciphertext
        byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
        ciphertext[0] ^= 0xFF;
        parts[3] = base64Url(ciphertext);
        return String.join(".", parts);
    }

    /**
     * Creates a JWE token wrapping a signed JWS access token using ECDH-ES key agreement.
     */
    public static String createEcdhEsJweWrappedAccessToken(PrivateKey signingKey, KeyPair ephemeralKeyPair,
            ECPublicKey recipientPublicKey, String enc, String issuer) {
        try {
            String innerJws = createSignedJws(signingKey, "RS256", issuer);
            return encryptAsEcdhEsJwe(innerJws, ephemeralKeyPair, recipientPublicKey, enc);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create ECDH-ES JWE", e);
        }
    }

    /**
     * Creates a JWE with DEFLATE compression (zip=DEF).
     */
    public static String createCompressedJwe(PrivateKey signingKey, PublicKey encryptionKey,
            String alg, String enc, String issuer) {
        String innerJws = createSignedJws(signingKey, "RS256", issuer);
        return createCompressedJweFromPlaintext(innerJws.getBytes(StandardCharsets.UTF_8),
                encryptionKey, alg, enc);
    }

    /**
     * Creates a JWE (zip=DEF) wrapping an arbitrary plaintext. Used to build a decompression-bomb
     * token whose compact form stays small while its decompressed content exceeds the decryptor's
     * decompressed-size ceiling.
     *
     * @param plaintext     the raw bytes to compress and encrypt
     * @param encryptionKey the public key to encrypt the CEK (RSA)
     * @param alg           the JWE key-management algorithm (e.g., "RSA-OAEP")
     * @param enc           the JWE content-encryption algorithm (e.g., "A256GCM")
     * @return the JWE compact serialization string
     */
    public static String createCompressedJweFromPlaintext(byte[] plaintext, PublicKey encryptionKey,
            String alg, String enc) {
        try {
            // Compress
            byte[] compressed = deflateCompress(plaintext);

            // Build header with zip
            Map<String, String> headerMap = new LinkedHashMap<>();
            headerMap.put("alg", alg);
            headerMap.put("enc", enc);
            headerMap.put("zip", "DEF");
            String headerJson = buildJson(headerMap);
            String encodedHeader = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));

            // Generate CEK and encrypt
            int cekBits = getCekBits(enc);
            byte[] cek = new byte[cekBits / 8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(cek);

            byte[] encryptedKey = encryptCek(cek, encryptionKey, alg);

            int ivLen = enc.contains("GCM") ? 12 : 16;
            byte[] iv = new byte[ivLen];
            random.nextBytes(iv);

            byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);

            byte[] ciphertext;
            byte[] authTag;

            if (enc.contains("GCM")) {
                byte[] result = encryptAesGcm(cek, iv, compressed, aad);
                ciphertext = Arrays.copyOfRange(result, 0, result.length - 16);
                authTag = Arrays.copyOfRange(result, result.length - 16, result.length);
            } else {
                int macKeyLen = cek.length / 2;
                byte[] macKey = Arrays.copyOfRange(cek, 0, macKeyLen);
                byte[] encKey = Arrays.copyOfRange(cek, macKeyLen, cek.length);
                ciphertext = encryptAesCbc(encKey, iv, compressed);
                authTag = computeAesCbcHsTag(macKey, getMacAlg(enc), aad, iv, ciphertext, macKeyLen);
            }

            return encodedHeader + "." +
                    base64Url(encryptedKey) + "." +
                    base64Url(iv) + "." +
                    base64Url(ciphertext) + "." +
                    base64Url(authTag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create compressed JWE", e);
        }
    }

    private static String encryptAsEcdhEsJwe(String plaintext, KeyPair ephemeralKeyPair,
            ECPublicKey recipientPublicKey, String enc) throws GeneralSecurityException {
        ECPublicKey ephemeralPublicKey = (ECPublicKey) ephemeralKeyPair.getPublic();

        // ECDH key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ephemeralKeyPair.getPrivate());
        ka.doPhase(recipientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // Derive CEK via ConcatKDF
        int keyLengthBits = getCekBits(enc);
        byte[] cek = ConcatKdf.derive(sharedSecret, keyLengthBits, enc, new byte[0], new byte[0]);

        // Build header with epk
        String epkJson = buildEpkJson(ephemeralPublicKey);
        Map<String, String> headerMap = new LinkedHashMap<>();
        headerMap.put("alg", "ECDH-ES");
        headerMap.put("enc", enc);
        // EPK needs special handling since it's a nested object
        String headerJson = "{\"alg\":\"ECDH-ES\",\"enc\":\"" + enc + "\",\"epk\":" + epkJson + "}";
        String encodedHeader = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));

        // ECDH-ES direct key agreement: encrypted key is empty
        byte[] encryptedKey = new byte[0];

        SecureRandom random = new SecureRandom();
        int ivLen = enc.contains("GCM") ? 12 : 16;
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);

        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext;
        byte[] authTag;

        if (enc.contains("GCM")) {
            byte[] result = encryptAesGcm(cek, iv, plaintextBytes, aad);
            ciphertext = Arrays.copyOfRange(result, 0, result.length - 16);
            authTag = Arrays.copyOfRange(result, result.length - 16, result.length);
        } else {
            int macKeyLen = cek.length / 2;
            byte[] macKey = Arrays.copyOfRange(cek, 0, macKeyLen);
            byte[] encKey = Arrays.copyOfRange(cek, macKeyLen, cek.length);
            ciphertext = encryptAesCbc(encKey, iv, plaintextBytes);
            authTag = computeAesCbcHsTag(macKey, getMacAlg(enc), aad, iv, ciphertext, macKeyLen);
        }

        return encodedHeader + "." +
                base64Url(encryptedKey) + "." +
                base64Url(iv) + "." +
                base64Url(ciphertext) + "." +
                base64Url(authTag);
    }

    private static String buildEpkJson(ECPublicKey publicKey) {
        String crv = switch (publicKey.getParams().getCurve().getField().getFieldSize()) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalArgumentException("Unsupported curve");
        };
        byte[] x = unsignedBytes(publicKey.getW().getAffineX(), getCoordinateLength(crv));
        byte[] y = unsignedBytes(publicKey.getW().getAffineY(), getCoordinateLength(crv));
        return "{\"kty\":\"EC\",\"crv\":\"" + crv + "\",\"x\":\"" +
                base64Url(x) + "\",\"y\":\"" + base64Url(y) + "\"}";
    }

    private static int getCoordinateLength(String crv) {
        return switch (crv) {
            case "P-256" -> 32;
            case "P-384" -> 48;
            case "P-521" -> 66;
            default -> throw new IllegalArgumentException("Unsupported curve: " + crv);
        };
    }

    private static byte[] unsignedBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) return bytes;
        if (bytes.length == length + 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        if (bytes.length < length) {
            byte[] padded = new byte[length];
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        }
        return bytes;
    }

    private static byte[] deflateCompress(byte[] data) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true); // nowrap=true for raw DEFLATE
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[4096];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
    }

    /**
     * Imports ConcatKdf for ECDH-ES test token creation.
     */
    private static final class ConcatKdf {
        static byte[] derive(byte[] sharedSecret, int keyLengthBits, String algorithmId,
                byte[] apu, byte[] apv) {
            return de.cuioss.sheriff.token.validation.jwe.ConcatKdf.derive(
                    sharedSecret, keyLengthBits, algorithmId, apu, apv);
        }
    }

    private static byte[] encryptCek(byte[] cek, PublicKey key, String alg) throws GeneralSecurityException {
        return switch (alg) {
            case "RSA-OAEP" -> {
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                yield cipher.doFinal(cek);
            }
            case "RSA-OAEP-256" -> {
                OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, oaepSpec);
                yield cipher.doFinal(cek);
            }
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };
    }

    private static byte[] encryptAesGcm(byte[] cek, byte[] iv, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        int keyLen = cek.length;
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, 0, keyLen, "AES"), spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] encryptAesCbc(byte[] encKey, byte[] iv, byte[] plaintext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    private static byte[] computeAesCbcHsTag(byte[] macKey, String macAlg, byte[] aad,
            byte[] iv, byte[] ciphertext, int macKeyLen)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(macKey, macAlg));
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        long aadBitLength = (long) aad.length * 8;
        byte[] al = new byte[8];
        for (int i = 7; i >= 0; i--) {
            al[i] = (byte) (aadBitLength & 0xFF);
            aadBitLength >>= 8;
        }
        mac.update(al);
        byte[] fullTag = mac.doFinal();
        return Arrays.copyOf(fullTag, macKeyLen);
    }

    private static int getCekBits(String enc) {
        return switch (enc) {
            case "A128GCM" -> 128;
            case "A256GCM" -> 256;
            case "A128CBC-HS256" -> 256;
            case "A256CBC-HS512" -> 512;
            default -> throw new IllegalArgumentException("Unknown enc: " + enc);
        };
    }

    private static String getMacAlg(String enc) {
        return switch (enc) {
            case "A128CBC-HS256" -> "HmacSHA256";
            case "A256CBC-HS512" -> "HmacSHA512";
            default -> throw new IllegalArgumentException("Not a CBC-HS enc: " + enc);
        };
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String buildJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }
}
