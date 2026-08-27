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
package de.cuioss.sheriff.token.client.dpop;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DPoP / mTLS application and binding tests for {@link SenderConstraint} ({@code CLIENT-11}).
 * <p>
 * Beyond the metadata-level binding assertions, these tests pin the <em>proof-driven</em> contract
 * the DPoP-wiring deliverable (H3) added: the emitted proof is decoded and its claims are asserted, so
 * a regression that stopped normalizing {@code htu}, stopped echoing the {@code DPoP-Nonce}, or stopped
 * binding a protected-resource proof to its token via {@code ath} would fail here rather than silently
 * degrade the sender-constraint.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("SenderConstraint DPoP / mTLS application and proof claims")
class SenderConstraintTest {

    private static final String HTM = "POST";
    private static final String HTU = "https://as.example.com/realms/demo/protocol/openid-connect/token";
    private static final String DPOP_HEADER = "DPoP";

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @Test
    @DisplayName("Should add a DPoP proof header and record the jkt binding for a DPoP constraint")
    void shouldApplyDpopHeaderAndBinding() {
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256");
        var constraint = SenderConstraint.dpop(proofGenerator);
        Map<String, String> headers = new HashMap<>();

        constraint.apply(HTM, HTU, headers);

        assertAll("dpop constraint",
                () -> assertTrue(headers.containsKey(DPOP_HEADER), "a DPoP proof header is added"),
                () -> assertEquals(3, headers.get(DPOP_HEADER).split("\\.").length,
                        "the header value is a compact DPoP proof JWT"),
                () -> assertEquals(ConstraintBinding.Method.DPOP, constraint.method(), "method is DPoP"),
                () -> assertEquals(proofGenerator.jkt(), constraint.binding().confirmation(),
                        "the binding confirms the proof-key jkt"),
                () -> assertEquals("jkt", constraint.binding().method().confirmationMember(),
                        "DPoP binds via cnf.jkt"));
    }

    @Test
    @DisplayName("Should add no request header for mTLS but record the certificate-thumbprint binding")
    void shouldApplyMtlsBindingWithoutHeader() {
        String thumbprint = Generators.letterStrings(20, 40).next();
        var constraint = SenderConstraint.mtls(thumbprint);
        Map<String, String> headers = new HashMap<>();

        constraint.apply(HTM, HTU, headers);

        assertAll("mtls constraint",
                () -> assertTrue(headers.isEmpty(), "mTLS binds at the TLS layer — no request header is added"),
                () -> assertEquals(ConstraintBinding.Method.MTLS, constraint.method(), "method is mTLS"),
                () -> assertEquals(thumbprint, constraint.binding().confirmation(),
                        "the binding confirms the certificate thumbprint"),
                () -> assertEquals("x5t#S256", constraint.binding().method().confirmationMember(),
                        "mTLS binds via cnf.x5t#S256"));
    }

    @Test
    @DisplayName("Should mint a fresh proof header on each application")
    void shouldMintFreshProofPerApplication() {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        Map<String, String> first = new HashMap<>();
        Map<String, String> second = new HashMap<>();

        constraint.apply(HTM, HTU, first);
        constraint.apply(HTM, HTU, second);

        assertNotEquals(first.get(DPOP_HEADER), second.get(DPOP_HEADER),
                "each application must produce a distinct, single-use proof");
    }

    @Test
    @DisplayName("Should carry no ath and no nonce on a plain token-endpoint proof")
    void shouldEmitTokenEndpointProofWithoutAthOrNonce() {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        Map<String, String> headers = new HashMap<>();

        constraint.apply(HTM, HTU, headers);

        String payload = decodePayload(headers.get(DPOP_HEADER));
        assertAll("token-endpoint proof",
                () -> assertTrue(payload.contains("\"htm\":\"POST\""), "the request method is bound"),
                () -> assertFalse(payload.contains("\"ath\""), "a token-endpoint proof carries no ath"),
                () -> assertFalse(payload.contains("\"nonce\""), "no nonce is echoed when none was challenged"));
    }

    @Test
    @DisplayName("Should echo a server-supplied DPoP-Nonce into the proof (RFC 9449 §8)")
    void shouldEchoNonceIntoProof() {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        String nonce = Generators.letterStrings(20, 40).next();
        Map<String, String> headers = new HashMap<>();

        constraint.apply(HTM, HTU, nonce, headers);

        String payload = decodePayload(headers.get(DPOP_HEADER));
        assertTrue(payload.contains("\"nonce\":\"" + nonce + "\""),
                "the challenged nonce is echoed into the retried proof");
    }

    @Test
    @DisplayName("Should normalize htu by stripping query and fragment (RFC 9449 §4.2)")
    void shouldNormalizeHtuStrippingQueryAndFragment() {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        Map<String, String> headers = new HashMap<>();

        constraint.apply(HTM, HTU + "?foo=bar&baz=qux#section", headers);

        String payload = decodePayload(headers.get(DPOP_HEADER));
        assertAll("htu normalization",
                () -> assertTrue(payload.contains("\"htu\":\"" + HTU + "\""),
                        "htu binds only scheme, authority and path"),
                () -> assertFalse(payload.contains("foo=bar"), "the query component is stripped"),
                () -> assertFalse(payload.contains("section"), "the fragment component is stripped"));
    }

    @Test
    @DisplayName("Should bind a protected-resource proof to its access token via the ath claim (RFC 9449 §4.3)")
    void shouldBindProtectedResourceProofViaAth() throws Exception {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        String accessToken = Generators.letterStrings(30, 60).next();
        Map<String, String> headers = new HashMap<>();

        constraint.applyProtectedResource("GET", HTU, accessToken, null, headers);

        String payload = decodePayload(headers.get(DPOP_HEADER));
        assertTrue(payload.contains("\"ath\":\"" + expectedAth(accessToken) + "\""),
                "ath is the base64url SHA-256 of the presented access token");
    }

    @Test
    @DisplayName("Should report the DPoP scheme for a DPoP token and Bearer for an mTLS token")
    void shouldReportAuthorizationScheme() {
        var dpop = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        var mtls = SenderConstraint.mtls(Generators.letterStrings(20, 40).next());

        assertAll("authorization scheme",
                () -> assertEquals("DPoP", dpop.authorizationScheme(),
                        "a DPoP-bound token is presented under the DPoP scheme (RFC 9449 §7.1)"),
                () -> assertEquals("Bearer", mtls.authorizationScheme(),
                        "an mTLS-bound token presents as a Bearer credential — mTLS binds at the TLS layer"));
    }

    @Test
    @DisplayName("Should reject null generator, null headers, and a null/blank protected-resource token")
    void shouldRejectInvalidInputs() {
        var constraint = SenderConstraint.dpop(new DpopProofGenerator(keyPair, "RS256"));
        Map<String, String> headers = new HashMap<>();
        assertAll("input guards",
                () -> assertThrows(NullPointerException.class, () -> SenderConstraint.dpop(null)),
                () -> assertThrows(NullPointerException.class,
                        () -> constraint.apply(HTM, HTU, null)),
                () -> assertThrows(NullPointerException.class,
                        () -> constraint.applyProtectedResource("GET", HTU, null, null, headers)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> constraint.applyProtectedResource("GET", HTU, "  ", null, headers)),
                () -> assertThrows(NullPointerException.class, () -> ConstraintBinding.mtls(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> ConstraintBinding.dpop("  ")));
    }

    /**
     * Decodes the payload (middle) segment of a compact DPoP proof JWT into its raw JSON string.
     */
    private static String decodePayload(String proof) {
        String[] segments = proof.split("\\.");
        return new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
    }

    /**
     * @return the RFC 9449 §4.3 {@code ath} value the proof must carry for {@code accessToken} — the
     *         base64url (unpadded) SHA-256 hash of its US-ASCII encoding.
     */
    private static String expectedAth(String accessToken) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
