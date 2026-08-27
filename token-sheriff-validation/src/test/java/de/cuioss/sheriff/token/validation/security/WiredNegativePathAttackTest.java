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
package de.cuioss.sheriff.token.validation.security;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.JweTestTokenFactory;
import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Wired negative-path attack tier (H4).
 * <p>
 * Every test here drives the <em>real</em> {@link TokenValidator} entry point with a crafted attack
 * and asserts the <em>specific</em> rejection {@link EventType} the corresponding defense emits — never
 * a trivially-true {@code >= 0} counter check. Each attack is constructed so that the assertion cannot
 * be satisfied by an incidental failure earlier in the pipeline (for example the embedded-JWK token is
 * re-signed so a naive verifier would accept it, and the cross-issuer substitution uses a real signature
 * from the wrong key rather than a corrupted one).
 * <p>
 * The defenses proven on the wired path:
 * <ul>
 *   <li>VTEST-2 — HMAC/RSA algorithm confusion (HS256 signed over the RSA public key)</li>
 *   <li>VTEST-3 — JWE decompression bomb ({@code zip:"DEF"} inflating past the 256&nbsp;KB ceiling)</li>
 *   <li>VTEST-6 — cross-issuer key substitution (same {@code kid}, different key material)</li>
 *   <li>VTEST-7 — JWE key-management algorithm allow-list ({@code RSA1_5})</li>
 *   <li>VTEST-8 — DPoP sender-binding (cnf.jkt mismatch, stale iat, and HS256 proof)</li>
 *   <li>VTEST-9 — embedded-JWK header injection with a re-signed token</li>
 *   <li>VTEST-10 — {@code alg} case-variant of "none" ({@code NoNe}) rejected by the allow-list</li>
 *   <li>VTEST-11 — over-depth JSON payload rejected during parsing (Nimbus CVE-2025-53864 class)</li>
 *   <li>VTEST-12 — cross-audience token rejected on {@code aud} (Argo CD CVE-2023-22482 class)</li>
 *   <li>VTEST-13 — JWE header downgrade {@code RSA-OAEP}&rarr;{@code RSA1_5} refused before decryption</li>
 *   <li>VTEST-14 — RSA-OAEP decryption failures are indistinguishable (Bleichenbacher-oracle class)</li>
 *   <li>VTEST-15 — client_id&rarr;azp fallback off by default; a token omitting azp is rejected</li>
 * </ul>
 * <p>
 * VTEST-10 through VTEST-15 were derived from the real-world CVEs catalogued in the
 * {@code doc/validation/cve-lessons-register.adoc} hardening backlog (items B1–B4).
 */
@DisplayName("Wired Negative-Path Attack Tests (H4)")
class WiredNegativePathAttackTest {

    private static final String TEST_ISSUER = "https://wired-attack-test.example.com";
    private static final String TEST_AUDIENCE = "test-audience";
    private static final String EXPECTED_CLIENT_ID = "wired-attack-client";
    private static final String DEFAULT_KEY_ID = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;
    private static final String RESOURCE_URI = "https://resource.example.org/protectedresource";
    private static final String RESOURCE_METHOD = "GET";

    @Test
    @DisplayName("VTEST-2: HMAC/RSA algorithm confusion is rejected as UNSUPPORTED_ALGORITHM")
    void shouldRejectHmacRsaAlgorithmConfusion() {
        // Attacker forges an HS256 token, using the issuer's RSA *public* key bytes as the HMAC secret.
        RSAPublicKey issuerPublicKey = (RSAPublicKey) InMemoryKeyMaterialHandler.getDefaultPublicKey();
        var hmacKey = new SecretKeySpec(issuerPublicKey.getEncoded(), "HmacSHA256");
        String forged = Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("attacker")
                .audience().add(TEST_AUDIENCE).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(hmacKey, Jwts.SIG.HS256)
                .compact();

        TokenValidator validator = plainValidator();
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.UNSUPPORTED_ALGORITHM, ex.getEventType(),
                "HS256-over-RSA-public-key confusion must be rejected as an unsupported algorithm");
    }

    @Test
    @DisplayName("VTEST-3: JWE decompression bomb is rejected as JWE_DECRYPTION_FAILED")
    void shouldRejectJweDecompressionBomb() {
        KeyPair jweKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        // A tiny compressed payload that inflates to 512 KB — past the decryptor's 256 KB ceiling.
        byte[] bomb = new byte[512 * 1024];
        Arrays.fill(bomb, (byte) 'A');
        String jwe = JweTestTokenFactory.createCompressedJweFromPlaintext(
                bomb, jweKeyPair.getPublic(), "RSA-OAEP", "A256GCM");

        TokenValidator validator = jweValidator(jweKeyPair.getPrivate());
        var request = AccessTokenRequest.of(jwe);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.JWE_DECRYPTION_FAILED, ex.getEventType(),
                "A JWE whose decompressed content exceeds the ceiling must be rejected before parsing");
    }

    @Test
    @DisplayName("VTEST-6: cross-issuer key substitution is rejected as SIGNATURE_VALIDATION_FAILED")
    void shouldRejectCrossIssuerKeySubstitution() {
        // Sign with an attacker RSA key but present the issuer's kid; the issuer is configured with a
        // different key under the same kid, so the real signature verifies against the wrong material.
        KeyPair attackerKeyPair = generateRsaKeyPair();
        String forged = Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("attacker")
                .audience().add(TEST_AUDIENCE).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(attackerKeyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        TokenValidator validator = plainValidator();
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.SIGNATURE_VALIDATION_FAILED, ex.getEventType(),
                "A real signature from a substituted key under the same kid must fail verification");
    }

    @Test
    @DisplayName("VTEST-7: unsupported JWE key-management algorithm is rejected as JWE_UNSUPPORTED_ALGORITHM")
    void shouldRejectUnsupportedJweAlgorithm() {
        KeyPair jweKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        // RSA1_5 (RSAES-PKCS1-v1_5) is off the allow-list; the alg check fires before any decryption.
        String header = base64Url("{\"alg\":\"RSA1_5\",\"enc\":\"A256GCM\"}".getBytes(StandardCharsets.UTF_8));
        String jwe = header + ".AAAA.AAAA.AAAA.AAAA";

        TokenValidator validator = jweValidator(jweKeyPair.getPrivate());
        var request = AccessTokenRequest.of(jwe);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.JWE_UNSUPPORTED_ALGORITHM, ex.getEventType(),
                "A JWE using an off-allow-list key-management algorithm must be rejected");
    }

    @Test
    @SuppressWarnings("java:S5778")
    // each lambda's non-assertion calls (dpopValidator()/dpopRequest()) are pure factories that never throw
    @DisplayName("VTEST-8: DPoP sender-binding violations are each rejected with their specific event")
    void shouldRejectDpopSenderBindingViolations() {
        KeyPair dpopKeyPair = generateRsaKeyPair();
        Map<String, Object> dpopJwk = rsaPublicKeyToJwkMap((RSAPublicKey) dpopKeyPair.getPublic());
        String boundThumbprint = JwkThumbprintUtil.computeThumbprint(dpopJwk);
        long now = System.currentTimeMillis() / 1000;

        // DP2 — cnf.jkt mismatch: the access token is bound to a *different* key thumbprint than the proof.
        String tokenWrongCnf = signedAccessToken("a-different-thumbprint-value");
        String freshProof = dpopProof(dpopKeyPair, dpopJwk, tokenWrongCnf, now);
        var mismatchEx = assertThrows(TokenValidationException.class,
                () -> dpopValidator().createAccessToken(dpopRequest(tokenWrongCnf, freshProof)));
        assertEquals(EventType.DPOP_THUMBPRINT_MISMATCH, mismatchEx.getEventType(),
                "A cnf.jkt not matching the proof key must be rejected as a thumbprint mismatch");

        // DP3 — stale iat: the proof is correctly bound but its iat is far outside the freshness window.
        String tokenBound = signedAccessToken(boundThumbprint);
        String staleProof = dpopProof(dpopKeyPair, dpopJwk, tokenBound, now - 100_000);
        var staleEx = assertThrows(TokenValidationException.class,
                () -> dpopValidator().createAccessToken(dpopRequest(tokenBound, staleProof)));
        assertEquals(EventType.DPOP_PROOF_EXPIRED, staleEx.getEventType(),
                "A DPoP proof with a stale iat must be rejected as expired");

        // DP4 — symmetric proof algorithm: an HS256 proof is off the asymmetric allow-list.
        String hsProof = hs256DpopProof(tokenBound);
        var hsEx = assertThrows(TokenValidationException.class,
                () -> dpopValidator().createAccessToken(dpopRequest(tokenBound, hsProof)));
        assertEquals(EventType.DPOP_PROOF_INVALID, hsEx.getEventType(),
                "An HS256 DPoP proof must be rejected as an invalid proof");
    }

    @Test
    @DisplayName("VTEST-9: embedded-JWK header injection with a re-signed token is rejected as UNSUPPORTED_ALGORITHM")
    void shouldRejectEmbeddedJwkHeaderInjection() {
        // Attacker embeds their own public key in the header and re-signs the token with the matching
        // private key, so a verifier that trusted the embedded key would accept it. The library must
        // reject any token carrying a jwk header outright, before ever reaching signature verification.
        // The jwk header parameter is carried as a String (JwtHeader stores it as a String for DSL-JSON
        // compatibility); the embedded key material below is the attacker public key.
        KeyPair attackerKeyPair = generateRsaKeyPair();
        RSAPublicKey attackerPublicKey = (RSAPublicKey) attackerKeyPair.getPublic();
        String embeddedKey = base64Url(toUnsignedBytes(attackerPublicKey.getModulus()));
        String headerJson = "{\"alg\":\"RS256\",\"kid\":\"%s\",\"jwk\":\"%s\"}".formatted(DEFAULT_KEY_ID, embeddedKey);
        String payloadJson = "{\"iss\":\"%s\",\"sub\":\"attacker\",\"aud\":\"%s\",\"iat\":%d,\"exp\":%d}".formatted(
                TEST_ISSUER, TEST_AUDIENCE,
                System.currentTimeMillis() / 1000, (System.currentTimeMillis() / 1000) + 3600);
        String signingInput = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String forged = signingInput + "." + base64Url(rsaSign(signingInput, attackerKeyPair.getPrivate()));

        TokenValidator validator = plainValidator();
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.UNSUPPORTED_ALGORITHM, ex.getEventType(),
                "A token carrying an embedded JWK header must be rejected regardless of a valid re-signature");
    }

    @Test
    @DisplayName("VTEST-10: an alg header case-variant of \"none\" is rejected as UNSUPPORTED_ALGORITHM")
    void shouldRejectNoneAlgorithmCaseVariant() {
        // The allow-list decides acceptance by exact membership, so every case-variant of "none"
        // (NoNe, nOnE, …) fails by construction — there is no case-insensitive block-list to bypass.
        long now = System.currentTimeMillis() / 1000;
        String headerJson = "{\"alg\":\"NoNe\",\"kid\":\"%s\"}".formatted(DEFAULT_KEY_ID);
        String payloadJson = "{\"iss\":\"%s\",\"sub\":\"attacker\",\"aud\":\"%s\",\"iat\":%d,\"exp\":%d}".formatted(
                TEST_ISSUER, TEST_AUDIENCE, now, now + 3600);
        String forged = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(payloadJson.getBytes(StandardCharsets.UTF_8)) + ".AAAA";

        TokenValidator validator = plainValidator();
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.UNSUPPORTED_ALGORITHM, ex.getEventType(),
                "A case-variant of the \"none\" algorithm must be rejected as unsupported");
    }

    @Test
    @DisplayName("VTEST-11: a payload nested past maxNestingDepth is rejected as JSON_STRUCTURE_BOUNDS_EXCEEDED")
    void shouldRejectOverDepthJsonPayload() {
        // A validly-signed token whose payload nests deeper than the configured limit — so a naive
        // verifier that trusted the signature would still be forced to parse the bomb. Token-Sheriff
        // bounds nesting independently of DSL-JSON, the check Nimbus JOSE+JWT lacked (CVE-2025-53864).
        long now = System.currentTimeMillis() / 1000;
        String payloadJson = "{\"iss\":\"%s\",\"sub\":\"s\",\"aud\":\"%s\",\"iat\":%d,\"exp\":%d,\"n\":%s}".formatted(
                TEST_ISSUER, TEST_AUDIENCE, now, now + 3600, deeplyNested(6));
        String headerJson = "{\"alg\":\"RS256\",\"kid\":\"%s\"}".formatted(DEFAULT_KEY_ID);
        String signingInput = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String forged = signingInput + "."
                + base64Url(rsaSign(signingInput, InMemoryKeyMaterialHandler.getDefaultPrivateKey()));

        TokenValidator validator = lowDepthValidator(3);
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED, ex.getEventType(),
                "A payload nested beyond maxNestingDepth must fail closed during parsing");
    }

    @Test
    @DisplayName("VTEST-12: an access token whose aud targets a different service is rejected as AUDIENCE_MISMATCH")
    void shouldRejectCrossAudienceToken() {
        // Same trusted issuer and a genuine signature, but the audience names a different resource
        // server — the Argo CD (CVE-2023-22482) / Symfony (CVE-2026-45069) class. Must be rejected on
        // the aud claim, never accepted on the strength of the signature alone.
        String forged = Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("legit-user")
                .audience().add("https://other-service.example.com").and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();

        TokenValidator validator = plainValidator(); // expectedAudience = TEST_AUDIENCE
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.AUDIENCE_MISMATCH, ex.getEventType(),
                "A validly-signed token for a different audience must be rejected on the aud claim");
    }

    @Test
    @DisplayName("VTEST-13: a JWE header downgraded from RSA-OAEP to RSA1_5 is rejected as JWE_UNSUPPORTED_ALGORITHM")
    void shouldRejectJweHeaderAlgorithmDowngrade() {
        // jose4j GHSA-jgvc-jfgh-rjvv: the attacker rewrites an RSA-OAEP header to RSA1_5 to reach a
        // padding oracle. Token-Sheriff validates the header alg against the allow-list before any
        // decryption, so the downgrade is refused rather than silently honored.
        KeyPair jweKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        String oaepJwe = JweTestTokenFactory.createJweWrappedAccessToken(
                InMemoryKeyMaterialHandler.getDefaultPrivateKey(), jweKeyPair.getPublic(),
                "RS256", "RSA-OAEP", "A256GCM", TEST_ISSUER, null);
        String[] parts = oaepJwe.split("\\.");
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8)
                .replace("\"RSA-OAEP\"", "\"RSA1_5\"");
        parts[0] = base64Url(header.getBytes(StandardCharsets.UTF_8));
        String downgraded = String.join(".", parts);

        TokenValidator validator = jweValidator(jweKeyPair.getPrivate());
        var request = AccessTokenRequest.of(downgraded);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.JWE_UNSUPPORTED_ALGORITHM, ex.getEventType(),
                "A header-driven downgrade to a rejected key-management algorithm must be refused before decryption");
    }

    @Test
    @DisplayName("VTEST-14: distinct RSA-OAEP decryption failures all surface the same JWE_DECRYPTION_FAILED event")
    void shouldKeepJweDecryptionFailuresIndistinguishable() {
        // Authlib CVE-2026-28490 / jose4j GHSA-jgvc-jfgh-rjvv: a distinguishable error path (padding
        // failure vs auth failure) is a Bleichenbacher oracle. All three failure modes below must
        // collapse to one indistinguishable event so an attacker learns nothing from the response.
        KeyPair jweKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        KeyPair wrongKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        TokenValidator validator = jweValidator(jweKeyPair.getPrivate());
        PrivateKey signingKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey();

        // (a) wrong decryption key: the CEK was wrapped for a different RSA key than the validator holds.
        String wrongKeyJwe = JweTestTokenFactory.createJweWrappedAccessToken(
                signingKey, wrongKeyPair.getPublic(), "RS256", "RSA-OAEP", "A256GCM", TEST_ISSUER, null);
        // (b) tampered ciphertext and (c) tampered auth tag: correct key, corrupted AES-GCM.
        String tamperedCiphertext = JweTestTokenFactory.createJweWithTamperedCiphertext(
                signingKey, jweKeyPair.getPublic(), TEST_ISSUER);
        String tamperedAuthTag = JweTestTokenFactory.createJweWithTamperedAuthTag(
                signingKey, jweKeyPair.getPublic(), TEST_ISSUER);

        EventType wrongKey = decryptionFailureEvent(validator, wrongKeyJwe);
        EventType badCiphertext = decryptionFailureEvent(validator, tamperedCiphertext);
        EventType badTag = decryptionFailureEvent(validator, tamperedAuthTag);

        assertEquals(EventType.JWE_DECRYPTION_FAILED, wrongKey,
                "A wrong-key OAEP unwrap must surface as JWE_DECRYPTION_FAILED");
        assertEquals(wrongKey, badCiphertext,
                "A tampered ciphertext must be indistinguishable from a wrong key");
        assertEquals(wrongKey, badTag,
                "A tampered auth tag must be indistinguishable from a wrong key");
    }

    @Test
    @DisplayName("VTEST-15: with the client_id→azp fallback off (default), a token omitting azp is rejected as MISSING_CLAIM")
    void shouldRejectClientIdAzpFallbackByDefault() {
        // RFC 9068 permits client_id to stand in for a missing azp. With the fallback now off by
        // default, a validly-signed token that carries only client_id (client identity) and omits
        // azp must be rejected — the same client-identity-as-authorization conflation as the
        // azp→aud fallback flipped in VTEST-12's backlog item.
        String forged = Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("legit-user")
                .audience().add(TEST_AUDIENCE).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .claim("client_id", EXPECTED_CLIENT_ID)
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();

        TokenValidator validator = clientIdValidator();
        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class, () -> validator.createAccessToken(request));
        assertEquals(EventType.MISSING_CLAIM, ex.getEventType(),
                "With the client_id→azp fallback disabled by default, a token omitting azp must be rejected");
    }

    // === Validators ===

    private TokenValidator plainValidator() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        return TokenValidator.builder().parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig).build();
    }

    private TokenValidator jweValidator(PrivateKey decryptionKey) {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        return TokenValidator.builder().parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig)
                .jweDecryptionConfig(JweDecryptionConfig.builder().defaultDecryptionKey(decryptionKey).build())
                .build();
    }

    private TokenValidator clientIdValidator() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .expectedClientId(EXPECTED_CLIENT_ID)
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        return TokenValidator.builder().parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig).build();
    }

    private TokenValidator lowDepthValidator(int maxNestingDepth) {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        return TokenValidator.builder()
                .parserConfig(ParserConfig.builder().maxNestingDepth(maxNestingDepth).build())
                .issuerConfig(issuerConfig).build();
    }

    private TokenValidator dpopValidator() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .dpopConfig(DpopConfig.builder().build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        return TokenValidator.builder().parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig).build();
    }

    // === Token / proof crafting ===

    private String signedAccessToken(String cnfThumbprint) {
        return Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("test-subject")
                .audience().add(TEST_AUDIENCE).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .claim("cnf", Map.of("jkt", cnfThumbprint))
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    private String dpopProof(KeyPair keyPair, Map<String, Object> jwkMap, String accessToken, long iatSeconds) {
        String headerJson = "{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":%s}".formatted(mapToJson(jwkMap));
        String bodyJson = "{\"jti\":\"%s\",\"iat\":%d,\"ath\":\"%s\",\"htm\":\"%s\",\"htu\":\"%s\"}".formatted(
                UUID.randomUUID(), iatSeconds, computeAth(accessToken), RESOURCE_METHOD, RESOURCE_URI);
        String signingInput = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(bodyJson.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + base64Url(rsaSign(signingInput, keyPair.getPrivate()));
    }

    private String hs256DpopProof(String accessToken) {
        String headerJson = "{\"typ\":\"dpop+jwt\",\"alg\":\"HS256\"}";
        String bodyJson = "{\"jti\":\"%s\",\"iat\":%d,\"ath\":\"%s\",\"htm\":\"%s\",\"htu\":\"%s\"}".formatted(
                UUID.randomUUID(), System.currentTimeMillis() / 1000, computeAth(accessToken),
                RESOURCE_METHOD, RESOURCE_URI);
        String signingInput = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(bodyJson.getBytes(StandardCharsets.UTF_8));
        return signingInput + ".c2lnbmF0dXJl";
    }

    private AccessTokenRequest dpopRequest(String accessToken, String proof) {
        return new AccessTokenRequest(accessToken, Map.of("dpop", List.of(proof)),
                RESOURCE_URI, RESOURCE_METHOD);
    }

    // === Low-level helpers ===

    private EventType decryptionFailureEvent(TokenValidator validator, String jwe) {
        var ex = assertThrows(TokenValidationException.class,
                () -> validator.createAccessToken(AccessTokenRequest.of(jwe)));
        return ex.getEventType();
    }

    private static String deeplyNested(int levels) {
        // Produces {"a":{"a":{ … 1 … }}} nested `levels` deep.
        return "{\"a\":".repeat(levels) + "1" + "}".repeat(levels);
    }

    private static byte[] rsaSign(String signingInput, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to RSA-sign", e);
        }
    }

    private static String computeAth(String accessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return base64Url(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }

    private static Map<String, Object> rsaPublicKeyToJwkMap(RSAPublicKey publicKey) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "RSA");
        map.put("n", base64Url(toUnsignedBytes(publicKey.getModulus())));
        map.put("e", base64Url(toUnsignedBytes(publicKey.getPublicExponent())));
        return map;
    }

    private static String mapToJson(Map<String, Object> map) {
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        return sb.append('}').toString();
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
