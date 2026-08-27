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
package de.cuioss.sheriff.token.client.auth;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link PrivateKeyJwtAuth} ({@code private_key_jwt}, RFC 7523) — deliverable 3.
 * <p>
 * The strategy signs a short-lived JWT client assertion with the client's RSA private key. These
 * tests reconstruct and cryptographically verify the emitted assertion, assert the mandatory header
 * and payload claims, confirm no shared secret is present, and reject unsupported signing
 * algorithms.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("private_key_jwt client authentication")
class PrivateKeyJwtAuthTest {

    private static final String ASSERTION_TYPE_JWT_BEARER =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final Base64.Decoder BASE64_URL = Base64.getUrlDecoder();

    private KeyPair keyPair;

    @BeforeEach
    void generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    private PrivateKeyJwtAuth auth(String clientId, String audience, String keyId, String algorithm) {
        return new PrivateKeyJwtAuth(clientId, audience, keyPair.getPrivate(), keyId, algorithm);
    }

    private static String decode(String segment) {
        return new String(BASE64_URL.decode(segment), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("Should report the private_key_jwt method")
    void shouldReportMethod() {
        var auth = auth(Generators.letterStrings(5, 12).next(), "https://as.example.com/token",
                Generators.letterStrings(3, 8).next(), "RS256");

        assertEquals(ClientAuthMethod.PRIVATE_KEY_JWT, auth.method(), "strategy must report private_key_jwt");
    }

    @Test
    @DisplayName("Should emit an RFC 7523 client assertion in the form body and carry no shared secret")
    void shouldEmitClientAssertion() {
        String clientId = Generators.letterStrings(5, 12).next();
        String audience = "https://as.example.com/token";
        var auth = auth(clientId, audience, Generators.letterStrings(3, 8).next(), "RS256");
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();

        auth.decorate(form, headers);

        assertAll("assertion form parameters",
                () -> assertEquals(ASSERTION_TYPE_JWT_BEARER, form.get("client_assertion_type"),
                        "assertion type must be the RFC 7523 jwt-bearer urn"),
                () -> assertTrue(form.containsKey("client_assertion"), "a client_assertion must be present"),
                () -> assertTrue(headers.isEmpty(), "no Authorization header for private_key_jwt"),
                () -> assertEquals(3, form.get("client_assertion").split("\\.").length, "the assertion must be a three-part JWS compact serialization"));
    }

    @Test
    @DisplayName("Should build a header and payload carrying the mandatory RFC 7523 claims")
    void shouldBuildAssertionClaims() {
        String clientId = Generators.letterStrings(5, 12).next();
        String audience = "https://as.example.com/token";
        String keyId = Generators.letterStrings(3, 8).next();
        var auth = auth(clientId, audience, keyId, "RS256");
        Map<String, String> form = new HashMap<>();

        auth.decorate(form, new HashMap<>());

        String[] parts = form.get("client_assertion").split("\\.");
        String header = decode(parts[0]);
        String payload = decode(parts[1]);
        assertAll("assertion claims",
                () -> assertTrue(header.contains("\"alg\":\"RS256\""), "header must declare the signing algorithm"),
                () -> assertTrue(header.contains("\"typ\":\"JWT\""), "header must declare the JWT type"),
                () -> assertTrue(header.contains("\"kid\":\"" + keyId + "\""), "header must carry the key id"),
                () -> assertTrue(payload.contains("\"iss\":\"" + clientId + "\""), "iss must be the client id"),
                () -> assertTrue(payload.contains("\"sub\":\"" + clientId + "\""), "sub must be the client id"),
                () -> assertTrue(payload.contains("\"aud\":\"" + audience + "\""), "aud must be the token endpoint"),
                () -> assertTrue(payload.contains("\"jti\":\""), "a unique jti must be present"),
                () -> assertTrue(payload.contains("\"iat\":"), "an issued-at must be present"),
                () -> assertTrue(payload.contains("\"exp\":"), "an expiry must be present"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512"})
    @DisplayName("Should produce a signature that verifies against the client public key for each RSA algorithm")
    void shouldProduceVerifiableSignature(String algorithm) throws Exception {
        var auth = auth(Generators.letterStrings(5, 12).next(), "https://as.example.com/token",
                Generators.letterStrings(3, 8).next(), algorithm);
        Map<String, String> form = new HashMap<>();
        auth.decorate(form, new HashMap<>());

        String[] parts = form.get("client_assertion").split("\\.");
        String signingInput = parts[0] + "." + parts[1];
        byte[] signature = BASE64_URL.decode(parts[2]);

        assertTrue(verify(algorithm, keyPair.getPublic(), signingInput, signature),
                "the assertion signature must verify against the client public key");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PS256", "PS384", "PS512"})
    @DisplayName("Should produce a verifiable RSASSA-PSS signature for each PS algorithm (L9)")
    void shouldProduceVerifiablePssSignature(String algorithm) {
        var auth = auth(Generators.letterStrings(5, 12).next(), "https://as.example.com/token",
                Generators.letterStrings(3, 8).next(), algorithm);
        Map<String, String> form = new HashMap<>();
        auth.decorate(form, new HashMap<>());

        String[] parts = form.get("client_assertion").split("\\.");
        String signingInput = parts[0] + "." + parts[1];
        byte[] signature = BASE64_URL.decode(parts[2]);

        assertAll("PS assertion",
                () -> assertTrue(decode(parts[0]).contains("\"alg\":\"" + algorithm + "\""),
                        "header must declare the PS algorithm"),
                () -> assertTrue(verifyPss(algorithm, keyPair.getPublic(), signingInput, signature),
                        "the RSASSA-PSS assertion signature must verify against the client public key"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ES384", "ES512"})
    @DisplayName("Should produce a verifiable ECDSA (P1363) signature for each ES algorithm (L9)")
    void shouldProduceVerifiableEcdsaSignature(String algorithm) throws Exception {
        KeyPair ecKeyPair = ecKeyPair(algorithm);
        var auth = new PrivateKeyJwtAuth(Generators.letterStrings(5, 12).next(),
                "https://as.example.com/token", ecKeyPair.getPrivate(),
                Generators.letterStrings(3, 8).next(), algorithm);
        Map<String, String> form = new HashMap<>();
        auth.decorate(form, new HashMap<>());

        String[] parts = form.get("client_assertion").split("\\.");
        String signingInput = parts[0] + "." + parts[1];
        byte[] signature = BASE64_URL.decode(parts[2]);

        assertAll("ES assertion",
                () -> assertTrue(decode(parts[0]).contains("\"alg\":\"" + algorithm + "\""),
                        "header must declare the ES algorithm"),
                () -> assertTrue(verifyEcdsa(algorithm, ecKeyPair.getPublic(), signingInput, signature),
                        "the ECDSA (P1363) assertion signature must verify against the client public key"));
    }

    @Test
    @DisplayName("Should reject an unsupported signing algorithm")
    void shouldRejectUnsupportedAlgorithm() {
        String clientId = Generators.letterStrings(5, 12).next();
        String keyId = Generators.letterStrings(3, 8).next();

        assertThrows(IllegalArgumentException.class,
                () -> auth(clientId, "https://as.example.com/token", keyId, "HS256"),
                "a non-RSA / unknown algorithm must be rejected at construction");
    }

    @Test
    @DisplayName("Should reject null constructor arguments")
    void shouldRejectNullArguments() {
        String clientId = Generators.letterStrings(5, 12).next();
        String audience = "https://as.example.com/token";
        String keyId = Generators.letterStrings(3, 8).next();
        PrivateKey key = keyPair.getPrivate();
        assertAll("null rejection",
                () -> assertThrows(NullPointerException.class,
                        () -> new PrivateKeyJwtAuth(null, audience, key, keyId, "RS256")),
                () -> assertThrows(NullPointerException.class,
                        () -> new PrivateKeyJwtAuth(clientId, null, key, keyId, "RS256")),
                () -> assertThrows(NullPointerException.class,
                        () -> new PrivateKeyJwtAuth(clientId, audience, null, keyId, "RS256")),
                () -> assertThrows(NullPointerException.class,
                        () -> new PrivateKeyJwtAuth(clientId, audience, key, null, "RS256")),
                () -> assertThrows(NullPointerException.class,
                        () -> new PrivateKeyJwtAuth(clientId, audience, key, keyId, null)));
    }

    private static boolean verify(String jwtAlgorithm, PublicKey publicKey, String signingInput, byte[] signature)
            throws Exception {
        String jca = switch (jwtAlgorithm) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> throw new IllegalArgumentException("unexpected algorithm: " + jwtAlgorithm);
        };
        Signature verifier = Signature.getInstance(jca);
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    private static boolean verifyPss(String jwtAlgorithm, PublicKey publicKey, String signingInput, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(pssSpec(jwtAlgorithm));
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    private static boolean verifyEcdsa(String jwtAlgorithm, PublicKey publicKey, String signingInput, byte[] signature)
            throws Exception {
        String jca = switch (jwtAlgorithm) {
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            case "ES512" -> "SHA512withECDSAinP1363Format";
            default -> throw new IllegalArgumentException("unexpected algorithm: " + jwtAlgorithm);
        };
        Signature verifier = Signature.getInstance(jca);
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    private static PSSParameterSpec pssSpec(String jwtAlgorithm) {
        return switch (jwtAlgorithm) {
            case "PS256" -> new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
            case "PS384" -> new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
            case "PS512" -> new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
            default -> throw new IllegalArgumentException("unexpected algorithm: " + jwtAlgorithm);
        };
    }

    private static KeyPair ecKeyPair(String jwtAlgorithm) throws Exception {
        String curve = switch (jwtAlgorithm) {
            case "ES256" -> "secp256r1";
            case "ES384" -> "secp384r1";
            case "ES512" -> "secp521r1";
            default -> throw new IllegalArgumentException("unexpected algorithm: " + jwtAlgorithm);
        };
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }
}
