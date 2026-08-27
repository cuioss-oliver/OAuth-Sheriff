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
package de.cuioss.sheriff.token.validation.dpop;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler.Algorithm;
import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DpopProofValidatorTest {

    private static final String TEST_ISSUER = "https://test-issuer.example.com";

    private SecurityEventCounter securityEventCounter;
    private DpopReplayProtection replayProtection;
    private DpopProofValidator validator;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        replayProtection = new DpopReplayProtection(300, 10_000);

        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .audienceValidationDisabled(true)
                .build();

        validator = new DpopProofValidator(issuerConfig, securityEventCounter, replayProtection, new SignatureTemplateManager(issuerConfig.getAlgorithmPreferences()), ParserConfig.builder().build(), new DslJson<>(new DslJson.Settings<>()));
    }

    @AfterEach
    void tearDown() {
        replayProtection.close();
    }

    // === Happy Path Tests ===

    @Test
    void shouldPassWhenNoDpopHeaderAndNotRequiredAndNoCnfJkt() {
        // Bearer mode: no DPoP header, not required, no cnf.jkt in access token
        DecodedJwt accessToken = createAccessTokenJwt(null); // no cnf.jkt
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token");

        assertDoesNotThrow(() -> validator.validate(request, accessToken, "dummy-token"));
    }

    @Test
    void shouldPassWithValidDpopProof() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                "GET", "https://resource.example.org/protectedresource");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)),
                "https://resource.example.org/protectedresource", "GET");

        assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
    }

    // === Rejection Tests ===

    @Test
    void shouldRejectWhenDpopRequiredButNoCnfJkt() {
        IssuerConfig requiredConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().required(true).build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .audienceValidationDisabled(true)
                .build();
        var requiredValidator = new DpopProofValidator(requiredConfig, securityEventCounter, replayProtection, new SignatureTemplateManager(requiredConfig.getAlgorithmPreferences()), ParserConfig.builder().build(), new DslJson<>(new DslJson.Settings<>()));

        DecodedJwt accessToken = createAccessTokenJwt(null); // no cnf.jkt
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token");

        var ex = assertThrows(TokenValidationException.class,
                () -> requiredValidator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_CNF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectWhenCnfJktPresentButNoDpopHeader() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token");

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectWhenDpopHeaderPresentButNoCnfJkt() {
        DecodedJwt accessToken = createAccessTokenJwt(null);
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                Map.of("dpop", List.of("some.dpop.proof")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_CNF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectInvalidDpopProofFormat() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                Map.of("dpop", List.of("not-a-jwt")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectWrongTypHeader() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with wrong typ
        String dpopProof = buildDpopProofWithCustomTyp(keyPair, jwkMap, "RS256", rawAccessToken, "jwt");

        AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectReplayedJti() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Use the same jti twice — need htm/htu in proofs since validateHtuHtm now rejects missing values
        String fixedJti = UUID.randomUUID().toString();
        String dpopProof1 = buildDpopProofWithJtiAndHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken, fixedJti,
                "GET", "https://resource.example.org/protectedresource");
        String dpopProof2 = buildDpopProofWithJtiAndHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken, fixedJti,
                "GET", "https://resource.example.org/protectedresource");

        AccessTokenRequest request1 = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof1)),
                "https://resource.example.org/protectedresource", "GET");
        AccessTokenRequest request2 = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof2)),
                "https://resource.example.org/protectedresource", "GET");

        // First should pass
        assertDoesNotThrow(() -> validator.validate(request1, accessToken, rawAccessToken));

        // Second should fail (replay)
        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request2, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_REPLAY_DETECTED, ex.getEventType());
    }

    @Test
    @DisplayName("DpopConfig build should enforce the replay-window invariant ttl >= proofMaxAge + clockSkew (M3)")
    void shouldEnforceReplayWindowInvariantOnBuild() {
        // Under defaults the effective replay TTL must cover the full proof freshness window
        // (proofMaxAge + clock skew), so a jti cannot expire while its proof is still fresh.
        DpopConfig defaults = DpopConfig.builder().build();
        assertTrue(
                defaults.getNonceCacheTtlSeconds() >= defaults.getProofMaxAgeSeconds() + DpopConfig.DEFAULT_CLOCK_SKEW_SECONDS,
                "Default replay TTL must cover proofMaxAge + clock skew");

        // A configured TTL smaller than the freshness window is widened up to it, closing the window.
        DpopConfig widened = DpopConfig.builder()
                .proofMaxAgeSeconds(600)
                .nonceCacheTtlSeconds(120)
                .build();
        assertEquals(600 + DpopConfig.DEFAULT_CLOCK_SKEW_SECONDS, widened.getNonceCacheTtlSeconds(),
                "A TTL shorter than proofMaxAge + clock skew must be widened to the freshness window");

        // A configured TTL that already covers the freshness window is preserved unchanged.
        DpopConfig preserved = DpopConfig.builder()
                .proofMaxAgeSeconds(300)
                .nonceCacheTtlSeconds(1000)
                .build();
        assertEquals(1000, preserved.getNonceCacheTtlSeconds(),
                "A TTL that already covers the freshness window must be preserved");
    }

    @ParameterizedTest(name = "Should honor a DPoP proof supplied under the \"{0}\" header (M4)")
    @ValueSource(strings = {"DPoP", "DPOP", "dpop", "Dpop"})
    @DisplayName("Should honor a DPoP proof regardless of header-name casing (M4)")
    void shouldHonorDpopHeaderRegardlessOfCasing(String headerName) {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                "GET", "https://resource.example.org/protectedresource");

        // Supply the proof under a non-canonical header casing; case-insensitive lookup must still
        // resolve it so DPoP is enforced rather than being silently downgraded to bearer mode (M4).
        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of(headerName, List.of(dpopProof)),
                "https://resource.example.org/protectedresource", "GET");

        assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken),
                "A DPoP proof under the '" + headerName + "' header must be honored, not downgraded to bearer mode");
    }

    @Test
    void shouldRejectExpiredIat() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with iat 10 minutes in the past (exceeds default 300s max age)
        long staleIat = (System.currentTimeMillis() / 1000) - 600;
        String dpopProof = buildDpopProofWithIat(keyPair, jwkMap, "RS256", rawAccessToken, staleIat);

        AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_EXPIRED, ex.getEventType());
    }

    @Test
    void shouldRejectWrongAth() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with ath for a different token
        String dpopProof = buildDpopProofWithAth(keyPair, jwkMap, "RS256", "different.access.token");

        AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_ATH_MISMATCH, ex.getEventType());
    }

    @Test
    void shouldRejectThumbprintMismatch() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());

        String rawAccessToken = "some.access.token";
        // Use a different thumbprint in the access token
        DecodedJwt accessToken = createAccessTokenJwt("wrong-thumbprint-value");

        String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                "GET", "https://resource.example.org/protectedresource");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)),
                "https://resource.example.org/protectedresource", "GET");

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_THUMBPRINT_MISMATCH, ex.getEventType());
    }

    @Test
    void shouldRejectInvalidSignature() {
        KeyPair keyPairForHeader = generateRsaKeyPair();
        KeyPair keyPairForSigning = generateRsaKeyPair(); // Different key!
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPairForHeader.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with header JWK from one key but signed with different key
        String dpopProof = buildDpopProofWithMismatchedKey(keyPairForSigning, jwkMap, "RS256", rawAccessToken);

        AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
    }

    @Test
    void shouldRejectMultipleDpopHeaders() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                Map.of("dpop", List.of("proof1", "proof2")));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
        assertTrue(ex.getMessage().contains("Multiple DPoP headers"));
    }

    @Test
    void shouldRejectOversizedDpopProof() {
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        // Create a proof string larger than 8192 bytes
        String oversizedProof = "a".repeat(8193);
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                Map.of("dpop", List.of(oversizedProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
        assertTrue(ex.getMessage().contains("maximum size"));
    }

    @Test
    void shouldRejectWhenDpopRequiredWithCnfJktButNoDpopHeader() {
        IssuerConfig requiredConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().required(true).build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .audienceValidationDisabled(true)
                .build();
        var requiredValidator = new DpopProofValidator(requiredConfig, securityEventCounter, replayProtection, new SignatureTemplateManager(requiredConfig.getAlgorithmPreferences()), ParserConfig.builder().build(), new DslJson<>(new DslJson.Settings<>()));

        // Required mode, access token has cnf.jkt but no DPoP header
        DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");
        AccessTokenRequest request = AccessTokenRequest.of("dummy-token");

        var ex = assertThrows(TokenValidationException.class,
                () -> requiredValidator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_MISSING, ex.getEventType());
    }

    @Test
    void shouldRejectFutureIat() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Build proof with iat 2 minutes in the future (exceeds -60s tolerance)
        long futureIat = (System.currentTimeMillis() / 1000) + 120;
        String dpopProof = buildDpopProofWithIat(keyPair, jwkMap, "RS256", rawAccessToken, futureIat);

        AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, rawAccessToken));
        assertEquals(EventType.DPOP_PROOF_EXPIRED, ex.getEventType());
    }

    static Stream<Arguments> invalidJwkHeaderProvider() {
        return Stream.of(
                Arguments.of("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\"}", "jwk", "missing jwk"),
                Arguments.of("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":{\"kty\":\"oct\",\"k\":\"secret\"}}", "Unsupported", "unsupported kty"),
                Arguments.of("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":{\"n\":\"abc\",\"e\":\"AQAB\"}}", "kty", "missing kty"));
    }

    @ParameterizedTest(name = "should reject proof with {2}")
    @MethodSource("invalidJwkHeaderProvider")
    void shouldRejectProofWithInvalidJwkHeader(String headerJson, String expectedMessageFragment, String description) {
        String thumbprint = "some-thumbprint";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        String bodyJson = """
                {"jti":"test-jti","iat":%d,"ath":"test-ath"}""".formatted(System.currentTimeMillis() / 1000);
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String body = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));
        String proof = header + "." + body + ".dummy-sig";

        AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                Map.of("dpop", List.of(proof)));

        var ex = assertThrows(TokenValidationException.class,
                () -> validator.validate(request, accessToken, "dummy-token"));
        assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
        assertTrue(ex.getMessage().contains(expectedMessageFragment));
    }

    @Test
    void shouldAcceptCaseInsensitiveTyp() {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

        String rawAccessToken = "some.access.token";
        DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

        // Use uppercase typ with htm/htu
        String dpopProof = buildDpopProofWithCustomTypAndHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken, "DPoP+JWT",
                "GET", "https://resource.example.org/protectedresource");

        AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                Map.of("dpop", List.of(dpopProof)),
                "https://resource.example.org/protectedresource", "GET");

        assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
    }

    // === Algorithm Variant Tests (Tier 1) ===

    @Nested
    @DisplayName("Algorithm Variant Tests")
    class AlgorithmVariantTests {

        @Test
        @DisplayName("Should pass with valid DPoP proof using ES256")
        void shouldPassWithValidDpopProofUsingES256() {
            PrivateKey ecPrivateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(Algorithm.ES256);
            ECPublicKey ecPublicKey = (ECPublicKey) InMemoryKeyMaterialHandler.getDefaultPublicKey(Algorithm.ES256);
            Map<String, Object> jwkMap = ecPublicKeyToJwkMap(ecPublicKey, "P-256", 32);
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProofWithJjwt(ecPrivateKey, jwkMap, Jwts.SIG.ES256, rawAccessToken,
                    "GET", "https://resource.example.org/protectedresource");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://resource.example.org/protectedresource", "GET");

            assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
        }

        @Test
        @DisplayName("Should pass with valid DPoP proof using EdDSA (Ed25519)")
        void shouldPassWithValidDpopProofUsingEdDSA() {
            PrivateKey edPrivateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(Algorithm.ED_DSA);
            EdECPublicKey edPublicKey = (EdECPublicKey) InMemoryKeyMaterialHandler.getDefaultPublicKey(Algorithm.ED_DSA);
            Map<String, Object> jwkMap = edDsaPublicKeyToJwkMap(edPublicKey);
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProofWithJjwt(edPrivateKey, jwkMap, Jwts.SIG.EdDSA, rawAccessToken,
                    "GET", "https://resource.example.org/protectedresource");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://resource.example.org/protectedresource", "GET");

            assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
        }

        @Test
        @DisplayName("Should reject DPoP proof with HMAC algorithm (HS256)")
        void shouldRejectHmacAlgorithm() {
            DecodedJwt accessToken = createAccessTokenJwt("some-thumbprint");

            // Build a proof with alg: HS256 — rejected before signature verification
            String headerJson = """
                    {"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"oct","k":"secret"}}""";
            String bodyJson = """
                    {"jti":"test-jti","iat":%d,"ath":"test-ath"}""".formatted(System.currentTimeMillis() / 1000);
            String header = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String body = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));
            String proof = header + "." + body + ".dummy-sig";

            AccessTokenRequest request = AccessTokenRequest.of("dummy-token",
                    Map.of("dpop", List.of(proof)));

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, "dummy-token"));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains("not supported"));
        }
    }

    // === Missing Required Claim Tests (Tier 1) ===

    @Nested
    @DisplayName("Missing Required Claim Tests")
    class MissingClaimTests {

        static Stream<Arguments> missingClaimProvider() {
            // Each entry: (includeJti, includeIat, includeAth, expectedClaimInMessage)
            return Stream.of(
                    Arguments.of(false, true, true, "jti"),
                    Arguments.of(true, false, true, "iat"),
                    Arguments.of(true, true, false, "ath")
            );
        }

        @ParameterizedTest(name = "Should reject DPoP proof with missing {3} claim")
        @MethodSource("missingClaimProvider")
        void shouldRejectProofWithMissingRequiredClaim(boolean includeJti, boolean includeIat,
                boolean includeAth, String expectedClaim) {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProofWithSelectiveClaims(keyPair, jwkMap, "RS256",
                    rawAccessToken, includeJti, includeIat, includeAth);

            AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)));

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains(expectedClaim));
        }
    }

    @Nested
    @DisplayName("Low/info DPoP security sweep (L1, L3, L5)")
    class DpopSecuritySweepTests {

        @Test
        @DisplayName("L1: an operator-tightened maxTokenSize is applied to the DPoP proof")
        void shouldRejectDpopProofExceedingTightenedParserBounds() {
            ParserConfig tightConfig = ParserConfig.builder().maxTokenSize(200).build();
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(TEST_ISSUER)
                    .dpopConfig(DpopConfig.builder().build())
                    .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            var tightValidator = new DpopProofValidator(issuerConfig, securityEventCounter, replayProtection,
                    new SignatureTemplateManager(issuerConfig.getAlgorithmPreferences()), tightConfig,
                    tightConfig.getDslJson());

            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);
            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);
            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                    "GET", "https://resource.example.org/protectedresource");
            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://resource.example.org/protectedresource", "GET");

            var ex = assertThrows(TokenValidationException.class,
                    () -> tightValidator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains("exceeds maximum size"),
                    "A proof larger than the operator-tightened maxTokenSize must be rejected");
        }

        @Test
        @DisplayName("L5: an htu differing only by case, default port, and dot-segments normalizes equal")
        void shouldAcceptHtuDifferingOnlyByCasePortAndDotSegments() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);
            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Upper-case host, explicit default port, and a dot-segment — all must normalize away.
            String messyHtu = "https://RESOURCE.Example.ORG:443/a/../protectedresource";
            String cleanRequestUri = "https://resource.example.org/protectedresource";
            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken, "GET", messyHtu);
            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)), cleanRequestUri, "GET");

            assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken),
                    "An htu differing only by case, default port, and dot-segments must normalize equal");
        }

        @Test
        @DisplayName("L5: an htu with a genuinely different host is still rejected")
        void shouldRejectHtuWithDifferentHost() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);
            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken, "GET",
                    "https://attacker.example.org/protectedresource");
            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://resource.example.org/protectedresource", "GET");

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_HTU_MISMATCH, ex.getEventType(),
                    "Normalization must not collapse genuinely different hosts");
        }

        @Test
        @DisplayName("L3: in-window jtis survive flood eviction and are still detected as replays")
        void shouldNotEvictInWindowJtisUnderFlood() {
            try (DpopReplayProtection floodProtection = new DpopReplayProtection(300, 2)) {
                assertTrue(floodProtection.checkAndStore("first-jti"), "A fresh jti is accepted");
                for (int i = 0; i < 20; i++) {
                    assertTrue(floodProtection.checkAndStore("flood-jti-" + i),
                            "Each flooding jti is fresh and accepted");
                }
                assertFalse(floodProtection.checkAndStore("first-jti"),
                        "An in-window jti must survive flood eviction and still be detected as a replay");
            }
        }
    }

    // === Helper Methods ===

    private DecodedJwt createAccessTokenJwt(String cnfJkt) {
        Map<String, Object> bodyMap = new HashMap<>();
        bodyMap.put("iss", TEST_ISSUER);
        bodyMap.put("sub", "test-subject");
        bodyMap.put("exp", (System.currentTimeMillis() / 1000) + 3600);
        bodyMap.put("iat", System.currentTimeMillis() / 1000);
        if (cnfJkt != null) {
            bodyMap.put("cnf", Map.of("jkt", cnfJkt));
        }

        var body = new MapRepresentation(bodyMap);
        var header = new JwtHeader(
                "RS256", null, "test-key-id", null, null, null, null, null, null, null);

        return new DecodedJwt(header, body, "dummy-sig", new String[]{"a", "b", "c"}, "a.b.c");
    }

    private String buildDpopProof(KeyPair keyPair, Map<String, Object> jwkMap, String alg, String accessToken) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofWithCustomTyp(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String typ) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, typ,
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofWithCustomTypAndHtuHtm(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String typ, String htm, String htu) {
        return buildDpopProofInternalWithHtuHtm(keyPair, jwkMap, alg, typ,
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken), htm, htu);
    }

    private String buildDpopProofWithJtiAndHtuHtm(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String jti, String htm, String htu) {
        return buildDpopProofInternalWithHtuHtm(keyPair, jwkMap, alg, "dpop+jwt",
                jti, System.currentTimeMillis() / 1000, computeAth(accessToken), htm, htu);
    }

    private String buildDpopProofWithIat(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, long iat) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), iat, computeAth(accessToken));
    }

    private String buildDpopProofWithAth(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessTokenForAth) {
        return buildDpopProofInternal(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessTokenForAth));
    }

    private String buildDpopProofWithMismatchedKey(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String accessToken) {
        return buildDpopProofInternal(signingKeyPair, headerJwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken));
    }

    private String buildDpopProofWithHtuHtm(KeyPair keyPair, Map<String, Object> jwkMap, String alg,
            String accessToken, String htm, String htu) {
        return buildDpopProofInternalWithHtuHtm(keyPair, jwkMap, alg, "dpop+jwt",
                UUID.randomUUID().toString(), System.currentTimeMillis() / 1000,
                computeAth(accessToken), htm, htu);
    }

    private String buildDpopProofInternalWithHtuHtm(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String typ,
            String jti, long iat, String ath, String htm, String htu) {
        // Build header JSON
        String jwkJson = mapToJson(headerJwkMap);
        String headerJson = """
                {"typ":"%s","alg":"%s","jwk":%s}""".formatted(typ, alg, jwkJson);

        // Build body JSON with htm and htu
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s","htm":"%s","htu":"%s"}""".formatted(jti, iat, ath, htm, htu);

        // Encode
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

        String dataToSign = encodedHeader + "." + encodedBody;

        // Sign
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(signingKeyPair.getPrivate());
            signer.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();

            String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);

            return dataToSign + "." + encodedSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    private String buildDpopProofInternal(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String typ,
            String jti, long iat, String ath) {
        // Build header JSON
        String jwkJson = mapToJson(headerJwkMap);
        String headerJson = """
                {"typ":"%s","alg":"%s","jwk":%s}""".formatted(typ, alg, jwkJson);

        // Build body JSON
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s"}""".formatted(jti, iat, ath);

        // Encode
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

        String dataToSign = encodedHeader + "." + encodedBody;

        // Sign
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(signingKeyPair.getPrivate());
            signer.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();

            String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);

            return dataToSign + "." + encodedSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    private String computeAth(String accessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String mapToJson(Map<String, Object> map) {
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }

    private Map<String, Object> rsaPublicKeyToJwkMap(RSAPublicKey publicKey) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "RSA");
        map.put("n", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getModulus())));
        map.put("e", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getPublicExponent())));
        return map;
    }

    private byte[] toUnsignedBytes(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // --- EC / EdDSA helpers ---

    private Map<String, Object> ecPublicKeyToJwkMap(ECPublicKey publicKey, String curve, int coordSize) {
        ECPoint w = publicKey.getW();
        byte[] xBytes = normalizeCoordinate(w.getAffineX().toByteArray(), coordSize);
        byte[] yBytes = normalizeCoordinate(w.getAffineY().toByteArray(), coordSize);
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "EC");
        map.put("crv", curve);
        map.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes));
        map.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes));
        return map;
    }

    private Map<String, Object> edDsaPublicKeyToJwkMap(EdECPublicKey publicKey) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "OKP");
        map.put("crv", publicKey.getParams().getName());
        map.put("x", InMemoryKeyMaterialHandler.encodeEdECPublicKey(publicKey));
        return map;
    }

    private byte[] normalizeCoordinate(byte[] coordinate, int expectedSize) {
        int startIndex = 0;
        while (startIndex < coordinate.length && coordinate[startIndex] == 0) {
            startIndex++;
        }
        byte[] result = new byte[expectedSize];
        int sourceLength = coordinate.length - startIndex;
        int destStart = Math.max(0, expectedSize - sourceLength);
        int copyLength = Math.min(sourceLength, expectedSize);
        System.arraycopy(coordinate, startIndex, result, destStart, copyLength);
        return result;
    }

    /**
     * Builds a DPoP proof JWT using jjwt for proper signature format handling (EC/EdDSA).
     */
    @SuppressWarnings("unchecked")
    private <A extends SignatureAlgorithm> String buildDpopProofWithJjwt(
            PrivateKey privateKey, Map<String, Object> jwkMap,
            A sigAlgorithm, String accessToken, String htm, String htu) {
        return Jwts.builder()
                .header().type("dpop+jwt").add("jwk", jwkMap).and()
                .claim("jti", UUID.randomUUID().toString())
                .claim("iat", System.currentTimeMillis() / 1000)
                .claim("ath", computeAth(accessToken))
                .claim("htm", htm)
                .claim("htu", htu)
                .signWith(privateKey, sigAlgorithm)
                .compact();
    }

    // === HTU/HTM Validation Tests ===

    @Nested
    @DisplayName("HTU/HTM Validation Tests")
    class HtuHtmValidationTests {

        @Test
        @DisplayName("Should reject when requestUri is null (htu/htm required for DPoP)")
        void shouldRejectWhenRequestUriIsNull() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Proof without htm/htu claims — now rejected because request URI and method are required
            String dpopProof = buildDpopProof(keyPair, jwkMap, "RS256", rawAccessToken);

            AccessTokenRequest request = AccessTokenRequest.of(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)));

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains("request URI and method are required"));
        }

        @Test
        @DisplayName("Should reject when requestMethod is blank (htu/htm required for DPoP)")
        void shouldRejectWhenRequestMethodIsBlank() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProof(keyPair, jwkMap, "RS256", rawAccessToken);

            // requestUri present but requestMethod blank -> now rejected
            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)), "https://api.example.com/resource", "");

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains("request URI and method are required"));
        }

        @Test
        @DisplayName("Should reject proof with missing htm claim when request has URI and method")
        void shouldRejectMissingHtmClaim() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Proof without htm/htu — will fail because request carries URI and method
            String dpopProof = buildDpopProof(keyPair, jwkMap, "RS256", rawAccessToken);

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://api.example.com/resource", "GET");

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_PROOF_INVALID, ex.getEventType());
            assertTrue(ex.getMessage().contains("htm"));
        }

        @Test
        @DisplayName("Should reject proof with mismatched htm (POST vs GET)")
        void shouldRejectMismatchedHtm() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Proof says POST, request says GET
            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                    "POST", "https://api.example.com/resource");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://api.example.com/resource", "GET");

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_HTM_MISMATCH, ex.getEventType());
        }

        @Test
        @DisplayName("Should reject proof with mismatched htu")
        void shouldRejectMismatchedHtu() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Proof says different URI than request
            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                    "GET", "https://api.example.com/other");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://api.example.com/resource", "GET");

            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.validate(request, accessToken, rawAccessToken));
            assertEquals(EventType.DPOP_HTU_MISMATCH, ex.getEventType());
        }

        @Test
        @DisplayName("Should accept proof with matching htm and htu")
        void shouldAcceptMatchingHtmAndHtu() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                    "GET", "https://api.example.com/resource");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://api.example.com/resource", "GET");

            assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
        }

        @Test
        @DisplayName("Should strip query string from htu for comparison")
        void shouldStripQueryStringFromHtu() {
            KeyPair keyPair = generateRsaKeyPair();
            Map<String, Object> jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
            String thumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);

            String rawAccessToken = "some.access.token";
            DecodedJwt accessToken = createAccessTokenJwt(thumbprint);

            // Proof htu has no query, request URI has query — should match after stripping
            String dpopProof = buildDpopProofWithHtuHtm(keyPair, jwkMap, "RS256", rawAccessToken,
                    "GET", "https://api.example.com/resource");

            AccessTokenRequest request = new AccessTokenRequest(rawAccessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    "https://api.example.com/resource?page=1&size=10", "GET");

            assertDoesNotThrow(() -> validator.validate(request, accessToken, rawAccessToken));
        }
    }

    /**
     * Builds a DPoP proof with selective claims (for testing missing claim validation).
     * Uses RSA signing with valid signature so validation reaches the claim checks.
     */
    private String buildDpopProofWithSelectiveClaims(KeyPair signingKeyPair, Map<String, Object> headerJwkMap,
            String alg, String rawAccessToken, boolean includeJti, boolean includeIat, boolean includeAth) {
        // Build header JSON
        String jwkJson = mapToJson(headerJwkMap);
        String headerJson = """
                {"typ":"dpop+jwt","alg":"%s","jwk":%s}""".formatted(alg, jwkJson);

        // Build body with selective claims
        var parts = new ArrayList<String>();
        if (includeJti) {
            parts.add("\"jti\":\"%s\"".formatted(UUID.randomUUID().toString()));
        }
        if (includeIat) {
            parts.add("\"iat\":%d".formatted(System.currentTimeMillis() / 1000));
        }
        if (includeAth) {
            parts.add("\"ath\":\"%s\"".formatted(computeAth(rawAccessToken)));
        }
        String bodyJson = "{" + String.join(",", parts) + "}";

        // Encode
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));

        String dataToSign = encodedHeader + "." + encodedBody;

        // Sign with RSA
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(signingKeyPair.getPrivate());
            signer.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();

            String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);

            return dataToSign + "." + encodedSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }
}
