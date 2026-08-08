/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.client.dpop;

import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.Serial;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Mechanics + fail-closed unit tests for {@link DpopProofGenerator} ({@code CLIENT-11}, RFC 9449) —
 * deliverable 8, generalized to the full RSA / EC P-256 / OKP Ed25519 proof-key matrix.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("DpopProofGenerator DPoP proof + replay defence")
class DpopProofGeneratorTest {

    private static final String HTM = "POST";
    private static final String HTU = "https://as.example.com/realms/demo/protocol/openid-connect/token";

    /** Fixed width of a P-256 affine coordinate, and of an Ed25519 raw public key. */
    private static final int COORDINATE_BYTES = 32;

    /** Length of the uncompressed P-256 point (0x04 || X || Y) that ends the X.509 encoding. */
    private static final int UNCOMPRESSED_POINT_BYTES = 65;

    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private KeyPair keyPair;
    private KeyPair ecKeyPair;
    private KeyPair okpKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        keyPair = rsa.generateKeyPair();

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = ec.generateKeyPair();

        okpKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "ES256", "EdDSA"})
    @DisplayName("Should build a signed dpop+jwt proof carrying the htm/htu/jti/iat claims and embedded JWK")
    void shouldBuildSignedProof(String algorithm) {
        KeyPair proofKey = proofKeyFor(algorithm);
        var proofGenerator = new DpopProofGenerator(proofKey, algorithm);

        String proof = proofGenerator.generateProof(HTM, HTU);

        String[] segments = proof.split("\\.");
        assertEquals(3, segments.length, "a DPoP proof is a three-segment compact JWT");
        String header = decode(segments[0]);
        String payload = decode(segments[1]);
        String expectedJwk = JwkThumbprintUtil.canonicalJson(expectedJwkMembers(proofKey.getPublic()));
        assertAll("proof structure",
                () -> assertTrue(header.contains("\"typ\":\"dpop+jwt\""), "header carries the dpop+jwt typ"),
                () -> assertTrue(header.contains("\"alg\":\"" + algorithm + "\""),
                        "header carries the signing algorithm"),
                () -> assertTrue(header.contains("\"jwk\":" + expectedJwk),
                        "header embeds the canonical proof public JWK"),
                () -> assertTrue(payload.contains("\"htm\":\"" + HTM + "\""), "payload binds the HTTP method"),
                () -> assertTrue(payload.contains("\"htu\":\"" + HTU + "\""), "payload binds the target URI"),
                () -> assertTrue(payload.contains("\"jti\":"), "payload carries a proof identifier"),
                () -> assertTrue(payload.contains("\"iat\":"), "payload carries the issue time"),
                () -> assertTrue(signatureVerifies(segments, proofKey.getPublic(), algorithm),
                        "the proof is signed by the proof key"));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"RS256", "RS384", "RS512", "PS256", "ES256", "EdDSA"})
    @DisplayName("Should expose a stable jkt computed over the key type's canonical JWK members")
    void shouldExposeJktOverCanonicalMembers(String algorithm) {
        KeyPair proofKey = proofKeyFor(algorithm);
        var first = new DpopProofGenerator(proofKey, algorithm);
        var second = new DpopProofGenerator(proofKey, algorithm);
        String expectedJkt = JwkThumbprintUtil.computeThumbprint(expectedJwkMembers(proofKey.getPublic()));

        assertAll("jkt",
                () -> assertTrue(first.jkt() != null && !first.jkt().isBlank(), "jkt is present"),
                () -> assertEquals(first.jkt(), second.jkt(),
                        "the same proof key yields the same RFC 7638 thumbprint"),
                () -> assertTrue(first.jkt().matches("[A-Za-z0-9_-]+"), "jkt is base64url without padding"),
                () -> assertEquals(expectedJkt, first.jkt(),
                        "jkt must be the thumbprint over this key type's canonical member set"));
    }

    @Test
    @DisplayName("Should derive a different jkt per key type so a thumbprint cannot be reused across keys")
    void shouldDeriveDistinctJktPerKeyType() {
        String rsaJkt = new DpopProofGenerator(keyPair, "RS256").jkt();
        String ecJkt = new DpopProofGenerator(ecKeyPair, "ES256").jkt();
        String okpJkt = new DpopProofGenerator(okpKeyPair, "EdDSA").jkt();

        assertAll("per-key-type thumbprints",
                () -> assertNotEquals(rsaJkt, ecJkt, "an EC jkt must differ from the RSA jkt"),
                () -> assertNotEquals(rsaJkt, okpJkt, "an OKP jkt must differ from the RSA jkt"),
                () -> assertNotEquals(ecJkt, okpJkt, "an OKP jkt must differ from the EC jkt"));
    }

    @Test
    @DisplayName("Should keep the RSA jkt stable across the RS256 and PS256 algorithms")
    void shouldKeepRsaJktStableAcrossRsaAlgorithms() {
        var rs256 = new DpopProofGenerator(keyPair, "RS256");
        var ps256 = new DpopProofGenerator(keyPair, "PS256");

        assertEquals(rs256.jkt(), ps256.jkt(),
                "the thumbprint binds the key, not the signing algorithm");
    }

    @Test
    @DisplayName("Should mint a distinct jti on every proof so no two proofs are replayable copies")
    void shouldMintDistinctJtiPerProof() {
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256");
        Set<String> seenJtis = new HashSet<>();

        for (int i = 0; i < 25; i++) {
            String payload = decode(proofGenerator.generateProof(HTM, HTU).split("\\.")[1]);
            assertTrue(seenJtis.add(extractJti(payload)), "each proof must carry a fresh, previously-unseen jti");
        }
    }

    @Test
    @DisplayName("Should fail closed and log when the jti source repeats an identifier (replay defence)")
    void shouldRejectJtiReuse() {
        String fixedJti = "static-jti-value";
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256", () -> fixedJti);

        String first = proofGenerator.generateProof(HTM, HTU);
        assertNotEquals(null, first, "the first proof with a given jti is emitted");
        assertThrows(IllegalStateException.class, () -> proofGenerator.generateProof(HTM, HTU),
                "re-emitting a proof with the same jti would be replayable and must fail closed");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "DPoP proof 'jti' reuse detected");
    }

    @Test
    @DisplayName("Should still detect jti reuse after many distinct proofs have been tracked")
    void shouldDetectReuseWithinBoundedWindow() {
        String[] state = {"first-jti"};
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256", () -> state[0]);
        proofGenerator.generateProof(HTM, HTU);
        for (int i = 0; i < 50; i++) {
            state[0] = "distinct-jti-" + i;
            proofGenerator.generateProof(HTM, HTU);
        }

        state[0] = "distinct-jti-49";
        assertThrows(IllegalStateException.class, () -> proofGenerator.generateProof(HTM, HTU),
                "a jti still tracked in the bounded LRU window is detected as reuse and fails closed");
    }

    @ParameterizedTest(name = "{0} with a {1} key")
    @CsvSource({
            "ES256, RSA",
            "EdDSA, RSA",
            "RS256, EC",
            "PS256, EC",
            "EdDSA, EC",
            "RS256, OKP",
            "PS256, OKP",
            "ES256, OKP"
    })
    @DisplayName("Should reject an algorithm that does not match the proof-key type")
    void shouldRejectAlgorithmKeyTypeMismatch(String algorithm, String keyType) {
        KeyPair mismatchedKey = keyPairOfType(keyType);

        assertThrows(IllegalArgumentException.class, () -> new DpopProofGenerator(mismatchedKey, algorithm),
                "%s must not be accepted with a %s proof key".formatted(algorithm, keyType));
    }

    @Test
    @DisplayName("Should reject an unsupported signing algorithm and an unsupported proof-key type")
    void shouldRejectInvalidConfiguration() throws Exception {
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(2048);
        KeyPair dsaKeyPair = dsa.generateKeyPair();

        assertAll("configuration guards",
                () -> assertThrows(IllegalArgumentException.class, () -> new DpopProofGenerator(keyPair, "HS256"),
                        "an unsupported signing algorithm is rejected"),
                () -> assertThrows(IllegalArgumentException.class, () -> new DpopProofGenerator(dsaKeyPair, "RS256"),
                        "a proof key that is neither RSA, EC P-256 nor OKP Ed25519 is rejected"));
    }

    @Test
    @DisplayName("Should reject an EC proof key on a curve other than P-256")
    void shouldRejectUnsupportedEcCurve() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384KeyPair = ec.generateKeyPair();

        assertThrows(IllegalArgumentException.class, () -> new DpopProofGenerator(p384KeyPair, "ES256"),
                "ES256 is defined over P-256 only");
    }

    @Test
    @DisplayName("Should reject an EC proof key on a different curve that shares the P-256 field size")
    void shouldRejectSameFieldSizeCurveOtherThanP256() {
        KeyPair secp256k1KeyPair = new KeyPair(new Secp256k1PublicKey(), ecKeyPair.getPrivate());

        assertThrows(IllegalArgumentException.class, () -> new DpopProofGenerator(secp256k1KeyPair, "ES256"),
                "secp256k1 shares P-256's 256-bit field size but is a different curve, so publishing it "
                        + "as crv:P-256 would be curve confusion");
    }

    @Test
    @DisplayName("Should reject a blank htm or htu")
    void shouldRejectBlankParameters() {
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256");

        assertAll("parameter guards",
                () -> assertThrows(IllegalArgumentException.class, () -> proofGenerator.generateProof("  ", HTU)),
                () -> assertThrows(IllegalArgumentException.class, () -> proofGenerator.generateProof(HTM, "  ")));
    }

    private KeyPair proofKeyFor(String algorithm) {
        return switch (algorithm) {
            case "RS256", "RS384", "RS512", "PS256" -> keyPair;
            case "ES256" -> ecKeyPair;
            case "EdDSA" -> okpKeyPair;
            default -> throw new IllegalStateException("no fixture for algorithm " + algorithm);
        };
    }

    private KeyPair keyPairOfType(String keyType) {
        return switch (keyType) {
            case "RSA" -> keyPair;
            case "EC" -> ecKeyPair;
            case "OKP" -> okpKeyPair;
            default -> throw new IllegalStateException("no fixture for key type " + keyType);
        };
    }

    /**
     * Verifies the proof signature against the proof public key, decoding each algorithm's JOSE
     * signature form. ES256 arrives as the IEEE P1363 concatenation, so it is verified with the
     * JDK-native P1363 signature variant rather than the DER-expecting one.
     */
    private boolean signatureVerifies(String[] segments, PublicKey publicKey, String algorithm) {
        try {
            Signature verifier = Signature.getInstance(switch (algorithm) {
                case "RS256" -> "SHA256withRSA";
                case "RS384" -> "SHA384withRSA";
                case "RS512" -> "SHA512withRSA";
                case "PS256" -> "RSASSA-PSS";
                case "ES256" -> "SHA256withECDSAinP1363Format";
                case "EdDSA" -> "Ed25519";
                default -> throw new IllegalStateException("no verifier for algorithm " + algorithm);
            });
            if ("PS256".equals(algorithm)) {
                verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            }
            verifier.initVerify(publicKey);
            verifier.update((segments[0] + "." + segments[1]).getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getUrlDecoder().decode(segments[2]));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Independently derives the JWK members the generator is expected to publish for a proof key.
     * The EC and OKP members are read out of the key's X.509 encoding rather than re-implementing the
     * production encoding, so the assertion is a genuine cross-check and not a copy of the code
     * under test.
     */
    private static Map<String, Object> expectedJwkMembers(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsaKey) {
            return Map.of(
                    "kty", "RSA",
                    "e", BASE64_URL.encodeToString(unsignedBytes(rsaKey.getPublicExponent())),
                    "n", BASE64_URL.encodeToString(unsignedBytes(rsaKey.getModulus())));
        }
        byte[] encoded = publicKey.getEncoded();
        if ("EC".equals(publicKey.getAlgorithm())) {
            // A P-256 SubjectPublicKeyInfo ends with the uncompressed point 0x04 || X(32) || Y(32). // NOSONAR java:S125 - explanatory prose describing byte layout, not commented-out code
            byte[] point = Arrays.copyOfRange(encoded, encoded.length - UNCOMPRESSED_POINT_BYTES, encoded.length);
            assertEquals(0x04, point[0] & 0xFF, "expected an uncompressed P-256 point in the X.509 encoding");
            return Map.of(
                    "kty", "EC",
                    "crv", "P-256",
                    "x", BASE64_URL.encodeToString(Arrays.copyOfRange(point, 1, 1 + COORDINATE_BYTES)),
                    "y", BASE64_URL.encodeToString(
                            Arrays.copyOfRange(point, 1 + COORDINATE_BYTES, UNCOMPRESSED_POINT_BYTES)));
        }
        // An Ed25519 SubjectPublicKeyInfo ends with the raw RFC 8032 32-byte public key.
        return Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", BASE64_URL.encodeToString(
                        Arrays.copyOfRange(encoded, encoded.length - COORDINATE_BYTES, encoded.length)));
    }

    private static byte[] unsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static String extractJti(String payload) {
        int start = payload.indexOf("\"jti\":\"") + "\"jti\":\"".length();
        int end = payload.indexOf('"', start);
        return payload.substring(start, end);
    }

    private static String decode(String segment) {
        return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
    }

    /**
     * A public key on curve secp256k1 — a 256-bit curve that is <em>not</em> P-256, and therefore the
     * case a field-size-only guard wrongly admits. SunEC dropped secp256k1 after JDK 15, so no
     * {@code KeyPairGenerator} can produce one; the key is assembled from the curve's published
     * domain parameters (SEC 2 §2.4.1) instead. The guard under test reads nothing but those
     * parameters, so the missing key material is immaterial to what is asserted.
     */
    private static final class Secp256k1PublicKey implements ECPublicKey {

        @Serial
        private static final long serialVersionUID = 1L;

        private static final BigInteger PRIME =
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        private static final BigInteger ORDER =
                new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        private static final ECPoint GENERATOR = new ECPoint(
                new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16));
        private static final ECParameterSpec PARAMS = new ECParameterSpec(
                new EllipticCurve(new ECFieldFp(PRIME), BigInteger.ZERO, BigInteger.valueOf(7)),
                GENERATOR, ORDER, 1);

        @Override
        public ECPoint getW() {
            return GENERATOR;
        }

        @Override
        public ECParameterSpec getParams() {
            return PARAMS;
        }

        @Override
        public String getAlgorithm() {
            return "EC";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
