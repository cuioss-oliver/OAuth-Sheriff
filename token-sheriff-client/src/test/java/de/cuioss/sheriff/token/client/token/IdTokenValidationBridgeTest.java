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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.JwtTokenTamperingUtil;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("IdTokenValidationBridge pipeline validation with nonce binding")
class IdTokenValidationBridgeTest {

    private static final String NONCE_CLAIM = "nonce";
    private static final String AT_HASH_CLAIM = "at_hash";
    private static final Pattern JWS_ALG_PATTERN = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");

    private TestTokenHolder holder;
    private IdTokenValidationBridge bridge;

    @BeforeEach
    void setUp() {
        holder = TestTokenGenerators.idTokens().next();
        TokenValidator validator = TokenValidator.builder().issuerConfig(holder.getIssuerConfig()).build();
        bridge = new IdTokenValidationBridge(validator);
    }

    @Test
    @DisplayName("Should validate an ID token whose nonce matches the flow nonce")
    void shouldValidateMatchingNonce() {
        String nonce = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));

        IdTokenContent content = bridge.validateIdToken(holder.getRawToken(), nonce);

        assertNotNull(content, "the validated ID token content must be returned on a nonce match");
    }

    @Test
    @DisplayName("Should reject an ID token whose nonce does not match the flow nonce")
    void shouldRejectNonceMismatch() {
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(Generators.letterStrings(20, 40).next()));
        String rawToken = holder.getRawToken();
        String expectedNonce = Generators.letterStrings(20, 40).next();

        var thrown = assertThrows(ClientProtocolException.class,
                () -> bridge.validateIdToken(rawToken, expectedNonce));
        assertNotNull(thrown.getMessage(), "the fail-closed rejection must carry a message");
    }

    @Test
    @DisplayName("Should reject an ID token that carries no nonce claim")
    void shouldRejectMissingNonce() {
        holder.withoutClaim(NONCE_CLAIM);
        String rawToken = holder.getRawToken();
        String expectedNonce = Generators.letterStrings(20, 40).next();

        assertThrows(ClientProtocolException.class,
                () -> bridge.validateIdToken(rawToken, expectedNonce));
    }

    @Test
    @DisplayName("Should reject an ID token minted for a foreign issuer")
    void shouldRejectForeignIssuer() {
        String nonce = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        holder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("https://attacker.example.com"));
        String rawToken = holder.getRawToken();

        assertThrows(TokenValidationException.class, () -> bridge.validateIdToken(rawToken, nonce));
    }

    @ParameterizedTest
    @EnumSource(JwtTokenTamperingUtil.TamperingStrategy.class)
    @DisplayName("Should reject an ID token whose JWS integrity was tampered (TEST-7)")
    void shouldRejectSignatureTampering(JwtTokenTamperingUtil.TamperingStrategy strategy) {
        String nonce = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        String tampered = JwtTokenTamperingUtil.applyTamperingStrategy(holder.getRawToken(), strategy);

        assertThrows(TokenValidationException.class, () -> bridge.validateIdToken(tampered, nonce),
                "signature tampering via " + strategy + " must fail pipeline validation, never reach the nonce check");
    }

    @Test
    @DisplayName("Should reject null construction and validation arguments")
    void shouldRejectNullArguments() {
        String nonce = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        String rawToken = holder.getRawToken();

        assertAll("null-guards",
                () -> assertThrows(NullPointerException.class, () -> new IdTokenValidationBridge(null)),
                () -> assertThrows(NullPointerException.class, () -> bridge.validateIdToken(null, nonce)),
                () -> assertThrows(NullPointerException.class, () -> bridge.validateIdToken(rawToken, null)));
    }

    @Test
    @DisplayName("Should accept an ID token whose at_hash binds the accompanying access token (M4)")
    void shouldAcceptMatchingAtHash() {
        String nonce = Generators.letterStrings(20, 40).next();
        String accessToken = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        holder.withClaim(AT_HASH_CLAIM, ClaimValue.forPlainString(atHash(holder.getRawToken(), accessToken)));
        String rawToken = holder.getRawToken();

        IdTokenContent content = bridge.validateIdToken(rawToken, nonce, accessToken);

        assertNotNull(content, "the validated ID token content must be returned when at_hash binds the access token");
    }

    @Test
    @DisplayName("Should reject an ID token whose at_hash does not bind the access token (M4)")
    void shouldRejectMismatchedAtHash() {
        String nonce = Generators.letterStrings(20, 40).next();
        String accessToken = Generators.letterStrings(20, 40).next();
        String otherAccessToken = Generators.letterStrings(41, 60).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        holder.withClaim(AT_HASH_CLAIM, ClaimValue.forPlainString(atHash(holder.getRawToken(), otherAccessToken)));
        String rawToken = holder.getRawToken();

        var thrown = assertThrows(ClientProtocolException.class,
                () -> bridge.validateIdToken(rawToken, nonce, accessToken));
        assertNotNull(thrown.getMessage(), "the fail-closed at_hash rejection must carry a message");
    }

    @Test
    @DisplayName("Should skip the at_hash check when the ID token asserts no at_hash (OIDC Core §3.1.3.6)")
    void shouldSkipAbsentAtHash() {
        String nonce = Generators.letterStrings(20, 40).next();
        String accessToken = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        holder.withoutClaim(AT_HASH_CLAIM);
        String rawToken = holder.getRawToken();

        IdTokenContent content = assertDoesNotThrow(() -> bridge.validateIdToken(rawToken, nonce, accessToken));

        assertNotNull(content, "an absent at_hash is not an error — there is simply nothing to bind");
    }

    @Test
    @DisplayName("Should reject a null access token on the at_hash-binding overload (M4)")
    void shouldRejectNullAccessToken() {
        String nonce = Generators.letterStrings(20, 40).next();
        holder.withClaim(NONCE_CLAIM, ClaimValue.forPlainString(nonce));
        String rawToken = holder.getRawToken();

        assertThrows(NullPointerException.class, () -> bridge.validateIdToken(rawToken, nonce, null));
    }

    /**
     * Computes the OIDC {@code at_hash} for {@code accessToken} using the digest the raw ID token's JWS
     * {@code alg} selects — mirroring the binding the production seam asserts (OIDC Core §3.1.3.6).
     */
    private static String atHash(String rawIdToken, String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance(shaAlgorithm(rawIdToken));
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            byte[] leftHalf = Arrays.copyOf(hash, hash.length / 2);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String shaAlgorithm(String rawIdToken) {
        String alg = jwsAlgorithm(rawIdToken);
        if (alg.endsWith("384")) {
            return "SHA-384";
        }
        if (alg.endsWith("512")) {
            return "SHA-512";
        }
        return "SHA-256";
    }

    private static String jwsAlgorithm(String rawIdToken) {
        int dot = rawIdToken.indexOf('.');
        if (dot <= 0) {
            return "";
        }
        String header = new String(Base64.getUrlDecoder().decode(rawIdToken.substring(0, dot)),
                StandardCharsets.UTF_8);
        Matcher matcher = JWS_ALG_PATTERN.matcher(header);
        return matcher.find() ? matcher.group(1) : "";
    }
}
