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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pipeline-level integration tests for DPoP validation.
 * <p>
 * These tests verify that DPoP validation is correctly wired into the
 * {@link de.cuioss.sheriff.token.validation.pipeline.AccessTokenValidationPipeline}
 * through {@link TokenValidator}, including cache-hit re-validation behavior.
 */
@DisplayName("DPoP Pipeline Integration Tests")
class DpopPipelineIntegrationTest {

    private static final String TEST_ISSUER = "https://dpop-pipeline-test.example.com";
    private static final String TEST_AUDIENCE = "test-audience";
    private static final String TEST_CLIENT_ID = "test-client";
    private static final String DEFAULT_KEY_ID = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;
    private static final String RESOURCE_URI = "https://resource.example.org/protectedresource";
    private static final String RESOURCE_METHOD = "GET";

    private KeyPair dpopClientKeyPair;
    private Map<String, Object> dpopJwkMap;
    private String dpopThumbprint;

    @BeforeEach
    void setUp() {
        dpopClientKeyPair = generateRsaKeyPair();
        dpopJwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) dpopClientKeyPair.getPublic());
        dpopThumbprint = JwkThumbprintUtil.computeThumbprint(dpopJwkMap);
    }

    @Test
    @DisplayName("Should validate access token with DPoP proof through full pipeline")
    void shouldValidateAccessTokenWithDpopProofThroughPipeline() {
        String accessToken = createSignedAccessToken(dpopThumbprint);
        String dpopProof = createDpopProof(dpopClientKeyPair, dpopJwkMap, accessToken);

        IssuerConfig issuerConfig = createDpopIssuerConfig();

        try (TokenValidator validator = TokenValidator.builder()
                     .issuerConfig(issuerConfig)
                     .build()) {
            AccessTokenRequest request = new AccessTokenRequest(accessToken,
                    Map.of("dpop", List.of(dpopProof)),
                    RESOURCE_URI, RESOURCE_METHOD);

            AccessTokenContent result = validator.createAccessToken(request);
            assertNotNull(result);
            assertEquals(TEST_ISSUER, result.getIssuer());
        }
    }

    @Test
    @DisplayName("Should validate fresh DPoP proof on cache hit")
    void shouldValidateFreshDpopProofOnCacheHit() {
        String accessToken = createSignedAccessToken(dpopThumbprint);
        IssuerConfig issuerConfig = createDpopIssuerConfig();

        try (TokenValidator validator = TokenValidator.builder()
                     .issuerConfig(issuerConfig)
                     .build()) {

            // First call — full validation, token gets cached
            String proof1 = createDpopProof(dpopClientKeyPair, dpopJwkMap, accessToken);
            AccessTokenRequest request1 = new AccessTokenRequest(accessToken,
                    Map.of("dpop", List.of(proof1)),
                    RESOURCE_URI, RESOURCE_METHOD);
            AccessTokenContent result1 = validator.createAccessToken(request1);

            // Second call — same token, NEW DPoP proof → succeeds via cache hit + fresh DPoP
            String proof2 = createDpopProof(dpopClientKeyPair, dpopJwkMap, accessToken);
            AccessTokenRequest request2 = new AccessTokenRequest(accessToken,
                    Map.of("dpop", List.of(proof2)),
                    RESOURCE_URI, RESOURCE_METHOD);
            AccessTokenContent result2 = validator.createAccessToken(request2);

            // Both return same token content (from cache)
            assertEquals(result1.getIssuer(), result2.getIssuer());
        }
    }

    @Test
    @DisplayName("Should reject replayed DPoP proof even on cache hit")
    void shouldRejectReplayedDpopProofOnCacheHit() {
        String accessToken = createSignedAccessToken(dpopThumbprint);
        IssuerConfig issuerConfig = createDpopIssuerConfig();

        try (TokenValidator validator = TokenValidator.builder()
                     .issuerConfig(issuerConfig)
                     .build()) {

            // First call — success, token cached, jti stored in replay protection
            String proof = createDpopProof(dpopClientKeyPair, dpopJwkMap, accessToken);
            AccessTokenRequest request1 = new AccessTokenRequest(accessToken,
                    Map.of("dpop", List.of(proof)),
                    RESOURCE_URI, RESOURCE_METHOD);
            assertNotNull(validator.createAccessToken(request1));

            // Second call — same proof (replayed jti) → fails even though token is cached
            AccessTokenRequest request2 = new AccessTokenRequest(accessToken,
                    Map.of("dpop", List.of(proof)),
                    RESOURCE_URI, RESOURCE_METHOD);
            var ex = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(request2));
            assertEquals(EventType.DPOP_REPLAY_DETECTED, ex.getEventType());
        }
    }

    @Test
    @DisplayName("Should pass bearer mode without DPoP through pipeline")
    void shouldPassBearerModeWithoutDpop() {
        // Access token WITHOUT cnf.jkt
        String accessToken = createSignedAccessTokenWithoutCnf();
        IssuerConfig issuerConfig = createDpopIssuerConfig();

        try (TokenValidator validator = TokenValidator.builder()
                     .issuerConfig(issuerConfig)
                     .build()) {

            // No DPoP header, no cnf.jkt — bearer mode pass-through
            AccessTokenContent result = validator.createAccessToken(AccessTokenRequest.of(accessToken));
            assertNotNull(result);
            assertEquals(TEST_ISSUER, result.getIssuer());
        }
    }

    // === Helper Methods ===

    private IssuerConfig createDpopIssuerConfig() {
        return IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .expectedClientId(TEST_CLIENT_ID)
                .dpopConfig(DpopConfig.builder().build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
    }

    private String createSignedAccessToken(String cnfJkt) {
        return Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("test-subject")
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .issuedAt(Date.from(Instant.now()))
                .audience().add(TEST_AUDIENCE).and()
                .claim("azp", TEST_CLIENT_ID)
                .claim("scope", "openid profile email")
                .claim("cnf", Map.of("jkt", cnfJkt))
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    private String createSignedAccessTokenWithoutCnf() {
        return Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).and()
                .issuer(TEST_ISSUER)
                .subject("test-subject")
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .issuedAt(Date.from(Instant.now()))
                .audience().add(TEST_AUDIENCE).and()
                .claim("azp", TEST_CLIENT_ID)
                .claim("scope", "openid profile email")
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    private String createDpopProof(KeyPair keyPair, Map<String, Object> jwkMap, String accessToken) {
        // Build header JSON
        String jwkJson = mapToJson(jwkMap);
        String headerJson = """
                {"typ":"dpop+jwt","alg":"RS256","jwk":%s}""".formatted(jwkJson);

        // Build body JSON with htm/htu for validateHtuHtm
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s","htm":"%s","htu":"%s"}""".formatted(
                UUID.randomUUID().toString(),
                System.currentTimeMillis() / 1000,
                computeAth(accessToken),
                RESOURCE_METHOD,
                RESOURCE_URI);

        // Encode
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));
        String dataToSign = encodedHeader + "." + encodedBody;

        // Sign with RSA
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
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
}
