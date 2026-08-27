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
import de.cuioss.sheriff.token.validation.jwks.JwksLoaderFactory;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import lombok.Getter;
import lombok.NonNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EdECPoint;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory key material handler for JWT token testing.
 * <p>
 * This class provides access to private and public keys used for signing and verifying tokens.
 * Unlike KeyMaterialHandler, this class:
 * <ul>
 *   <li>Creates keys on the fly</li>
 *   <li>Stores keys in static fields instead of the filesystem</li>
 *   <li>Supports multiple algorithms (RS256, RS384, RS512)</li>
 *   <li>Uses standard JDK providers for key material generation</li>
 * </ul>
 * <p>
 * All access to key materials should be through this class.
 */
public class InMemoryKeyMaterialHandler {

    private static final CuiLogger LOGGER = new CuiLogger(InMemoryKeyMaterialHandler.class);

    /**
     * Default key ID used when no key ID is specified.
     */
    public static final String DEFAULT_KEY_ID = "test-key-id";

    /**
     * Supported signature algorithms.
     */
    public enum Algorithm {
        RS256(Jwts.SIG.RS256),
        RS384(Jwts.SIG.RS384),
        RS512(Jwts.SIG.RS512),
        ES256(Jwts.SIG.ES256),
        ES384(Jwts.SIG.ES384),
        ES512(Jwts.SIG.ES512),
        PS256(Jwts.SIG.PS256),
        PS384(Jwts.SIG.PS384),
        PS512(Jwts.SIG.PS512),
        ED_DSA(Jwts.SIG.EdDSA);

        @Getter
        private final SignatureAlgorithm algorithm;

        Algorithm(SignatureAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        /**
         * Gets the JWK algorithm name.
         *
         * @return the algorithm name as used in JWK
         */
        public String getJwkAlgorithmName() {
            if (this == ED_DSA) {
                return "EdDSA";
            }
            return name();
        }
    }

    // Static maps to store key pairs for different algorithms
    private static final Map<Algorithm, Map<String, KeyPair>> KEY_PAIRS = new ConcurrentHashMap<>();

    // Static initializer
    static {

        // Initialize key pair maps for each algorithm
        for (Algorithm alg : Algorithm.values()) {
            KEY_PAIRS.put(alg, new ConcurrentHashMap<>());
        }

        // Generate default key pairs for each algorithm
        for (Algorithm alg : Algorithm.values()) {
            generateKeyPair(alg, DEFAULT_KEY_ID);
        }
    }

    /**
     * Generates a key pair for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm to use
     * @param keyId     the key ID
     * @return the generated key pair
     */
    private static KeyPair generateKeyPair(Algorithm algorithm, String keyId) {
        try {
            LOGGER.debug("Generating key pair for algorithm %s with key ID %s", algorithm, keyId);
            KeyPair keyPair = algorithm.getAlgorithm().keyPair().build();
            KEY_PAIRS.get(algorithm).put(keyId, keyPair);
            return keyPair;
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new IllegalStateException("Failed to generate key pair for algorithm " + algorithm, e);
        }
    }

    /**
     * Gets the private key for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId     the key ID
     * @return the private key
     */
    public static PrivateKey getPrivateKey(Algorithm algorithm, String keyId) {
        return getKeyPair(algorithm, keyId).getPrivate();
    }

    /**
     * Gets the public key for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId     the key ID
     * @return the public key
     */
    public static PublicKey getPublicKey(Algorithm algorithm, String keyId) {
        return getKeyPair(algorithm, keyId).getPublic();
    }

    /**
     * Gets the key pair for the specified algorithm and key ID.
     * If the key pair doesn't exist, it will be generated.
     *
     * @param algorithm the algorithm
     * @param keyId     the key ID
     * @return the key pair
     */
    private static KeyPair getKeyPair(Algorithm algorithm, String keyId) {
        Map<String, KeyPair> keyPairsForAlg = KEY_PAIRS.get(algorithm);
        if (keyPairsForAlg.containsKey(keyId)) {
            return keyPairsForAlg.get(keyId);
        }
        return generateKeyPair(algorithm, keyId);
    }

    /**
     * Gets the default private key for the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return the default private key
     */
    public static PrivateKey getDefaultPrivateKey(Algorithm algorithm) {
        return getPrivateKey(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Gets the default public key for the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return the default public key
     */
    public static PublicKey getDefaultPublicKey(Algorithm algorithm) {
        return getPublicKey(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Gets the default private key for RS256.
     *
     * @return the default private key for RS256
     */
    public static PrivateKey getDefaultPrivateKey() {
        return getDefaultPrivateKey(Algorithm.RS256);
    }

    /**
     * Gets the default public key for RS256.
     *
     * @return the default public key for RS256
     */
    public static PublicKey getDefaultPublicKey() {
        return getDefaultPublicKey(Algorithm.RS256);
    }

    /**
     * Creates a JWKS string for the specified algorithm and key ID.
     *
     * @param algorithm the algorithm
     * @param keyId     the key ID
     * @return a JWKS string containing the public key
     */
    public static String createJwks(Algorithm algorithm, String keyId) {
        PublicKey publicKey = getPublicKey(algorithm, keyId);
        return createJwksFromKey(publicKey, keyId, algorithm.getJwkAlgorithmName());
    }

    /**
     * Creates a JWKS string for the default key of the specified algorithm.
     *
     * @param algorithm the algorithm
     * @return a JWKS string containing the default public key
     */
    public static String createDefaultJwks(Algorithm algorithm) {
        return createJwks(algorithm, DEFAULT_KEY_ID);
    }

    /**
     * Creates a JWKS string for the default RS256 key.
     *
     * @return a JWKS string containing the default RS256 public key
     */
    public static String createDefaultJwks() {
        return createDefaultJwks(Algorithm.RS256);
    }

    /**
     * Creates a JWKS string from a public key.
     *
     * @param publicKey the public key
     * @param keyId     the key ID
     * @param algorithm the algorithm name (e.g., "RS256", "ES256", "PS256")
     * @return a JWKS string
     */
    private static String createJwksFromKey(PublicKey publicKey, String keyId, String algorithm) {
        if (publicKey instanceof RSAPublicKey key) {
            return createJwksFromRsaKey(key, keyId, algorithm);
        } else if (algorithm.startsWith("ES")) {
            return createJwksFromEcKey(keyId, algorithm);
        } else if (algorithm.startsWith("PS")) {
            // PS algorithms use RSA keys with RSASSA-PSS signature scheme
            return createJwksFromRsaKey((RSAPublicKey) publicKey, keyId, algorithm);
        } else if ("EdDSA".equals(algorithm)) {
            return createJwksFromOkpKey((EdECPublicKey) publicKey, keyId);
        } else {
            throw new IllegalArgumentException("Unsupported key type for algorithm: " + algorithm);
        }
    }

    /**
     * Creates a JWKS string from an RSA public key.
     *
     * @param publicKey the RSA public key
     * @param keyId     the key ID
     * @param algorithm the algorithm name (e.g., "RS256", "PS256")
     * @return a JWKS string
     */
    private static String createJwksFromRsaKey(RSAPublicKey publicKey, String keyId, String algorithm) {
        // Extract the modulus and exponent
        byte[] modulusBytes = publicKey.getModulus().toByteArray();
        byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();

        // Remove leading zero byte if present (BigInteger sign bit)
        if (modulusBytes.length > 0 && modulusBytes[0] == 0) {
            byte[] tmp = new byte[modulusBytes.length - 1];
            System.arraycopy(modulusBytes, 1, tmp, 0, tmp.length);
            modulusBytes = tmp;
        }

        // Base64 URL encode
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

        // Create JWKS JSON with the specified key ID and algorithm
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\",\"alg\":\"%s\"}]}".formatted(
                keyId, n, e, algorithm);
    }

    /**
     * Creates a JWKS string from an EC public key.
     *
     * @param keyId     the key ID
     * @param algorithm the algorithm name (e.g., "ES256")
     * @return a JWKS string
     */
    private static String createJwksFromEcKey(String keyId, String algorithm) {
        // Get the actual EC public key to extract coordinates
        PublicKey publicKey = getPublicKey(Algorithm.valueOf(algorithm), keyId);

        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Expected ECPublicKey for algorithm: " + algorithm);
        }

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

        // Extract the x and y coordinates from the EC public key point
        ECPoint w = ecPublicKey.getW();
        byte[] xBytes = w.getAffineX().toByteArray();
        byte[] yBytes = w.getAffineY().toByteArray();

        // Determine coordinate size based on algorithm
        int coordSize = switch (algorithm) {
            case "ES256" -> 32; // P-256: 256 bits / 8 = 32 bytes
            case "ES384" -> 48; // P-384: 384 bits / 8 = 48 bytes  
            case "ES512" -> 66; // P-521: 521 bits / 8 = 65.125 -> 66 bytes
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algorithm);
        };

        // Pad or trim coordinates to the expected size
        xBytes = normalizeCoordinate(xBytes, coordSize);
        yBytes = normalizeCoordinate(yBytes, coordSize);

        // Base64 URL encode the coordinates
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes);
        String y = Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes);

        // Determine the curve name based on the algorithm
        String curve = switch (algorithm) {
            case "ES256" -> "P-256";
            case "ES384" -> "P-384";
            case "ES512" -> "P-521";
            default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algorithm);
        };

        // Create JWKS JSON with the specified key ID, algorithm, curve, and coordinates
        return "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\",\"alg\":\"%s\"}]}".formatted(
                keyId, curve, x, y, algorithm);
    }

    /**
     * Creates a JWKS string from an EdDSA (OKP) public key.
     *
     * @param publicKey the EdEC public key
     * @param keyId     the key ID
     * @return a JWKS string
     */
    private static String createJwksFromOkpKey(EdECPublicKey publicKey, String keyId) {
        return "{\"keys\":[%s]}".formatted(createOkpJwkObject(publicKey, keyId));
    }

    /**
     * Creates a single OKP JWK JSON object string from an EdDSA public key.
     *
     * @param publicKey the EdEC public key
     * @param keyId     the key ID
     * @return a JWK JSON object string (without surrounding array)
     */
    private static String createOkpJwkObject(EdECPublicKey publicKey, String keyId) {
        String curve = publicKey.getParams().getName();
        String x = encodeEdECPublicKey(publicKey);
        return "{\"kty\":\"OKP\",\"kid\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",\"alg\":\"EdDSA\"}".formatted(keyId, curve, x);
    }

    /**
     * Encodes an EdEC public key to its RFC 8032 little-endian representation as a base64url string.
     * Converts from BigInteger's big-endian format to EdDSA's little-endian format with the
     * x-coordinate parity bit set in the high bit of the last byte.
     *
     * @param publicKey the EdEC public key
     * @return the base64url-encoded key material (JWK "x" parameter)
     */
    public static String encodeEdECPublicKey(EdECPublicKey publicKey) {
        String curve = publicKey.getParams().getName();
        EdECPoint point = publicKey.getPoint();
        BigInteger y = point.getY();
        boolean xOdd = point.isXOdd();

        int keySize;
        if ("Ed25519".equals(curve)) {
            keySize = 32;
        } else if ("Ed448".equals(curve)) {
            keySize = 57;
        } else {
            throw new IllegalArgumentException("Unsupported EdDSA curve: " + curve);
        }
        byte[] yBytes = y.toByteArray();
        byte[] rawKey = new byte[keySize];

        // Reverse byte order: BigInteger is big-endian, EdDSA uses little-endian
        int srcStart = yBytes.length > 0 && yBytes[0] == 0 ? 1 : 0;
        int srcLen = yBytes.length - srcStart;
        for (int i = 0; i < srcLen && i < keySize; i++) {
            rawKey[i] = yBytes[yBytes.length - 1 - i];
        }

        if (xOdd) {
            rawKey[keySize - 1] |= (byte) 0x80;
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawKey);
    }

    /**
     * Normalizes a coordinate byte array to the expected size for the curve.
     * Removes leading zero bytes from BigInteger encoding and pads to the correct size.
     */
    private static byte[] normalizeCoordinate(byte[] coordinate, int expectedSize) {
        // Remove leading zero bytes (BigInteger sign bit)
        int startIndex = 0;
        while (startIndex < coordinate.length && coordinate[startIndex] == 0) {
            startIndex++;
        }

        // Create result array of expected size
        byte[] result = new byte[expectedSize];

        // Copy the coordinate data, right-aligned (padding with zeros on the left if needed)
        int sourceLength = coordinate.length - startIndex;
        int destStart = Math.max(0, expectedSize - sourceLength);
        int copyLength = Math.min(sourceLength, expectedSize);

        System.arraycopy(coordinate, startIndex, result, destStart, copyLength);

        return result;
    }

    /**
     * Creates a JwksLoader for the specified algorithm and key ID.
     *
     * @param algorithm            the algorithm
     * @param keyId                the key ID
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createJwksLoader(Algorithm algorithm, String keyId, SecurityEventCounter securityEventCounter) {
        String jwksContent = createJwks(algorithm, keyId);
        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        loader.initJWKSLoader(securityEventCounter);
        return loader;
    }

    /**
     * Creates a JwksLoader for the default key of the specified algorithm.
     *
     * @param algorithm            the algorithm
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader(Algorithm algorithm, SecurityEventCounter securityEventCounter) {
        return createJwksLoader(algorithm, DEFAULT_KEY_ID, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default RS256 key.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader(SecurityEventCounter securityEventCounter) {
        return createDefaultJwksLoader(Algorithm.RS256, securityEventCounter);
    }

    /**
     * Creates a JwksLoader for the default RS256 key with a new SecurityEventCounter.
     *
     * @return a JwksLoader instance
     */
    public static JwksLoader createDefaultJwksLoader() {
        return createDefaultJwksLoader(new SecurityEventCounter());
    }

    /**
     * Creates a multi-algorithm JWKS string containing keys for all supported algorithms.
     *
     * @return a JWKS string containing keys for all supported algorithms
     */
    public static String createMultiAlgorithmJwks() {
        StringBuilder jwksBuilder = new StringBuilder("{\"keys\":[");
        boolean first = true;

        for (Algorithm alg : Algorithm.values()) {
            PublicKey publicKey = getDefaultPublicKey(alg);
            String algName = alg.getJwkAlgorithmName();

            // Create JWK JSON based on the algorithm type
            if (!first) {
                jwksBuilder.append(",");
            }

            if (algName.startsWith("RS") || algName.startsWith("PS")) {
                // RSA or RSA-PSS key
                RSAPublicKey rsaKey = (RSAPublicKey) publicKey;

                // Extract the modulus and exponent
                byte[] modulusBytes = rsaKey.getModulus().toByteArray();
                byte[] exponentBytes = rsaKey.getPublicExponent().toByteArray();

                // Remove leading zero byte if present (BigInteger sign bit)
                if (modulusBytes.length > 0 && modulusBytes[0] == 0) {
                    byte[] tmp = new byte[modulusBytes.length - 1];
                    System.arraycopy(modulusBytes, 1, tmp, 0, tmp.length);
                    modulusBytes = tmp;
                }

                // Base64 URL encode
                String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
                String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

                jwksBuilder.append("{\"kty\":\"RSA\",\"kid\":\"").append(alg.name()).append("\",\"n\":\"")
                        .append(n).append("\",\"e\":\"").append(e).append("\",\"alg\":\"")
                        .append(algName).append("\"}");
            } else if (algName.startsWith("ES")) {
                // EC key - extract real coordinates
                if (!(publicKey instanceof ECPublicKey)) {
                    throw new IllegalArgumentException("Expected ECPublicKey for algorithm: " + algName);
                }

                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

                // Extract the x and y coordinates from the EC public key point
                ECPoint w = ecPublicKey.getW();
                byte[] xBytes = w.getAffineX().toByteArray();
                byte[] yBytes = w.getAffineY().toByteArray();

                // Determine coordinate size based on algorithm
                int coordSize = switch (algName) {
                    case "ES256" -> 32; // P-256: 256 bits / 8 = 32 bytes
                    case "ES384" -> 48; // P-384: 384 bits / 8 = 48 bytes  
                    case "ES512" -> 66; // P-521: 521 bits / 8 = 65.125 -> 66 bytes
                    default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algName);
                };

                // Pad or trim coordinates to the expected size
                xBytes = normalizeCoordinate(xBytes, coordSize);
                yBytes = normalizeCoordinate(yBytes, coordSize);

                // Base64 URL encode the coordinates
                String x = Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes);
                String y = Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes);

                String curve = switch (algName) {
                    case "ES256" -> "P-256";
                    case "ES384" -> "P-384";
                    case "ES512" -> "P-521";
                    default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algName);
                };

                jwksBuilder.append("{\"kty\":\"EC\",\"kid\":\"").append(alg.name())
                        .append("\",\"crv\":\"").append(curve)
                        .append("\",\"x\":\"").append(x)
                        .append("\",\"y\":\"").append(y)
                        .append("\",\"alg\":\"").append(algName).append("\"}");
            } else if ("EdDSA".equals(algName)) {
                // OKP (EdDSA) key
                if (!(publicKey instanceof EdECPublicKey edKey)) {
                    throw new IllegalArgumentException("Expected EdECPublicKey for algorithm: " + algName);
                }
                jwksBuilder.append(createOkpJwkObject(edKey, alg.name()));
            } else {
                throw new IllegalArgumentException("Unsupported algorithm type: " + algName);
            }

            first = false;
        }

        jwksBuilder.append("]}");
        return jwksBuilder.toString();
    }

    /**
     * Creates a JwksLoader containing keys for all supported algorithms.
     *
     * @param securityEventCounter the security event counter
     * @return a JwksLoader instance with keys for all supported algorithms
     */
    public static JwksLoader createMultiAlgorithmJwksLoader(@NonNull SecurityEventCounter securityEventCounter) {
        String jwksContent = createMultiAlgorithmJwks();
        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        loader.initJWKSLoader(securityEventCounter);
        return loader;
    }

    /**
     * Creates a JwksLoader containing keys for all supported algorithms with a new SecurityEventCounter.
     *
     * @return a JwksLoader instance with keys for all supported algorithms
     */
    public static JwksLoader createMultiAlgorithmJwksLoader() {
        return createMultiAlgorithmJwksLoader(new SecurityEventCounter());
    }

    /**
     * Container for key material belonging to a specific issuer.
     * This allows creating multiple distinct key sets for benchmarking issuer resolution.
     */
    @Getter
    public static class IssuerKeyMaterial {
        private final String issuerIdentifier;
        private final String keyId;
        private final Algorithm algorithm;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final String jwks;

        public IssuerKeyMaterial(String issuerIdentifier, String keyId, Algorithm algorithm) {
            this.issuerIdentifier = issuerIdentifier;
            this.keyId = keyId;
            this.algorithm = algorithm;

            // Generate unique key pair for this issuer
            KeyPair keyPair = generateKeyPair(algorithm, issuerIdentifier + "-" + keyId);
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();

            // Create JWKS for this issuer's key
            this.jwks = createJwksFromKey(publicKey, keyId, algorithm.getJwkAlgorithmName());
        }
    }

    /**
     * Creates multiple issuer key materials for benchmarking issuer resolution overhead.
     * Each issuer gets its own unique key pair.
     *
     * @param count     number of issuers to create
     * @param algorithm algorithm to use for all issuers
     * @return array of IssuerKeyMaterial instances
     */
    public static IssuerKeyMaterial[] createMultipleIssuers(int count, Algorithm algorithm) {
        IssuerKeyMaterial[] issuers = new IssuerKeyMaterial[count];

        for (int i = 0; i < count; i++) {
            String issuerIdentifier = "https://test-issuer-" + i + ".example.com";
            String keyId = "issuer-" + i + "-key";
            issuers[i] = new IssuerKeyMaterial(issuerIdentifier, keyId, algorithm);
        }

        return issuers;
    }

    /**
     * Creates multiple issuer key materials with RS256 algorithm.
     *
     * @param count number of issuers to create
     * @return array of IssuerKeyMaterial instances
     */
    public static IssuerKeyMaterial[] createMultipleIssuers(int count) {
        return createMultipleIssuers(count, Algorithm.RS256);
    }
}