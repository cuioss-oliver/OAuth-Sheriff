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

import de.cuioss.sheriff.token.commons.transport.JwkKey;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for handling JWK (JSON Web Key) operations.
 * <p>
 * This class provides methods for parsing and validating RSA, EC, and OKP keys from JWK format.
 * It isolates the low-level cryptographic operations from the JWKSKeyLoader class.
 * <p>
 * This class uses standard JDK cryptographic providers for key parsing and validation.
 * It supports all standard elliptic curves (P-256, P-384, P-521), RSA keys,
 * and OKP (Octet Key Pair) keys for EdDSA (Ed25519, Ed448)
 * as defined in RFC 7517 (JSON Web Key), RFC 7518 (JSON Web Algorithms),
 * and RFC 8037 (CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE).
 * <p>
 * All operations use the standard JDK cryptographic providers available in Java 21+,
 * ensuring excellent compatibility with GraalVM native image compilation.
 * EdDSA support leverages JEP 339 (Edwards-Curve Digital Signature Algorithm)
 * available natively in Java 15+.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkKeyHandler {

    private static final String MESSAGE = "Invalid Base64 URL encoded value for '%s'";

    /**
     * Minimum accepted RSA key size in bits (M1). RSA moduli shorter than 2048 bits are
     * cryptographically too weak to trust for signature verification and are rejected on every
     * key-parsing path (JWKS and DPoP embedded JWK). Shared with {@code KeyProcessor} and
     * {@code DpopProofValidator} so the threshold is defined exactly once.
     */
    public static final int MIN_RSA_KEY_SIZE_BITS = 2048;

    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";
    private static final String OKP_KEY_TYPE = "OKP";
    private static final String EDDSA_ALGORITHM = "EdDSA";
    private static final Set<String> SUPPORTED_OKP_CURVES = Set.of("Ed25519", "Ed448");

    // Cache for KeyFactory instances to improve performance
    private static final Map<String, KeyFactory> KEY_FACTORY_CACHE = new ConcurrentHashMap<>();


    /**
     * Parses an RSA public key from a JwkKey record.
     *
     * @param jwk the JwkKey record containing RSA parameters
     * @return the parsed RSA public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseRsaKey(JwkKey jwk) throws InvalidKeySpecException {
        // Use JwkKey's transformation methods with proper validation
        BigInteger exponent = jwk.getExponentAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("e")));
        BigInteger modulus = jwk.getModulusAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("n")));

        // Reject RSA keys weaker than 2048 bits (M1): sub-2048 moduli are cryptographically too
        // weak to trust for signature verification.
        if (modulus.bitLength() < MIN_RSA_KEY_SIZE_BITS) {
            throw new InvalidKeySpecException(
                    "RSA key modulus is %d bits; minimum accepted is %d bits".formatted(
                            modulus.bitLength(), MIN_RSA_KEY_SIZE_BITS));
        }

        // Create RSA public key
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = getKeyFactory(RSA_KEY_TYPE);
        return factory.generatePublic(spec);
    }


    /**
     * Parse an EC key from a JwkKey record.
     *
     * @param jwk the JwkKey record containing EC parameters
     * @return the EC public key
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    public static PublicKey parseEcKey(JwkKey jwk) throws InvalidKeySpecException {
        // Use JwkKey's transformation methods with proper validation
        String curve = jwk.getCrv()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("crv")));
        BigInteger x = jwk.getXCoordinateAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("x")));
        BigInteger y = jwk.getYCoordinateAsBigInteger()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("y")));

        // Create EC point
        ECPoint point = new ECPoint(x, y);

        // Get EC parameter spec for the curve
        ECParameterSpec params = getEcParameterSpec(curve);

        // Create EC public key
        ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
        KeyFactory factory = getKeyFactory(EC_KEY_TYPE);
        return factory.generatePublic(spec);
    }

    /**
     * Parses an OKP (Octet Key Pair) public key from a JwkKey record.
     * OKP keys are used for EdDSA signatures (Ed25519/Ed448) as defined in
     * <a href="https://datatracker.ietf.org/doc/html/rfc8037">RFC 8037</a>.
     * <p>
     * The key reconstruction follows the EdDSA public key format:
     * the {@code x} field contains the raw public key bytes in little-endian order,
     * with the sign bit encoded in the most significant bit of the last byte.
     *
     * @param jwk the JwkKey record containing OKP parameters (crv, x)
     * @return the parsed EdDSA public key
     * @throws InvalidKeySpecException if the key specification is invalid or the curve is unsupported
     */
    public static PublicKey parseOkpKey(JwkKey jwk) throws InvalidKeySpecException {
        // Validate curve
        String curve = jwk.getCrv()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("crv")));
        if (!SUPPORTED_OKP_CURVES.contains(curve)) {
            throw new InvalidKeySpecException("OKP curve %s is not supported. Supported curves: %s".formatted(
                    curve, SUPPORTED_OKP_CURVES));
        }

        // Get raw public key bytes
        byte[] rawBytes = jwk.getXCoordinateAsBytes()
                .orElseThrow(() -> new InvalidKeySpecException(MESSAGE.formatted("x")));

        // Reconstruct EdECPublicKey from raw bytes (RFC 8032 encoding)
        // The last byte contains the sign bit in its MSB
        boolean xOdd = (rawBytes[rawBytes.length - 1] & 0x80) != 0;

        // Clear the sign bit and reverse byte order (little-endian to big-endian for BigInteger)
        byte[] yBytes = rawBytes.clone();
        yBytes[yBytes.length - 1] &= 0x7F;
        reverseByteArray(yBytes);
        BigInteger y = new BigInteger(1, yBytes);

        try {
            NamedParameterSpec paramSpec = new NamedParameterSpec(curve);
            EdECPoint point = new EdECPoint(xOdd, y);
            EdECPublicKeySpec keySpec = new EdECPublicKeySpec(paramSpec, point);
            KeyFactory factory = getKeyFactory(EDDSA_ALGORITHM);
            return factory.generatePublic(keySpec);
        } catch (IllegalStateException e) {
            throw new InvalidKeySpecException("Failed to reconstruct EdDSA public key for curve " + curve, e);
        }
    }

    /**
     * Determines the EdDSA algorithm name for OKP keys.
     * Both Ed25519 and Ed448 use the single JWS algorithm identifier "EdDSA"
     * as defined in RFC 8037. The actual curve is determined by the key.
     *
     * @return always "EdDSA" for supported OKP curves
     */
    public static String determineOkpAlgorithm() {
        return EDDSA_ALGORITHM;
    }

    /**
     * Reverses a byte array in place (for little-endian to big-endian conversion).
     */
    private static void reverseByteArray(byte[] array) {
        for (int i = 0, j = array.length - 1; i < j; i++, j--) {
            byte tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }

    /**
     * Get the EC parameter spec for a given curve using standard JDK providers.
     *
     * @param curve the curve name (e.g., "P-256", "P-384", "P-521")
     * @return the EC parameter spec
     * @throws InvalidKeySpecException if the curve is not supported
     */
    private static ECParameterSpec getEcParameterSpec(String curve) throws InvalidKeySpecException {
        // Map JWK curve name to standard JDK curve name
        String jdkCurveName = switch (curve) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> null;
        };

        if (jdkCurveName == null) {
            throw new InvalidKeySpecException("EC curve " + curve + " is not supported");
        }

        try {
            // Use standard JDK AlgorithmParameters to get the curve parameters
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(jdkCurveName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new InvalidKeySpecException("Failed to get EC parameters for curve: " + curve, e);
        }
    }

    /**
     * Get a KeyFactory instance for the specified algorithm.
     * Uses a cache to avoid creating new instances repeatedly.
     *
     * @param algorithm the algorithm name
     * @return the KeyFactory instance
     * @throws IllegalStateException if the algorithm is not available
     */
    private static KeyFactory getKeyFactory(String algorithm) {
        return KEY_FACTORY_CACHE.computeIfAbsent(algorithm, alg -> {
            try {
                return KeyFactory.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Failed to create KeyFactory for " + alg, e);
            }
        });
    }

    /**
     * Determine the EC algorithm based on the curve.
     *
     * @param curve the curve name
     * @return the algorithm name
     * @throws IllegalArgumentException if the curve is not supported
     */
    public static String determineEcAlgorithm(String curve) {
        return switch (curve) {
            case "P-256" -> "ES256";
            case "P-384" -> "ES384";
            case "P-521" -> "ES512";
            default -> throw new IllegalArgumentException("Unsupported EC curve: " + curve);
        };
    }
}
