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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for validating protection against the "Psychic Signature" vulnerability (CVE-2022-21449).
 * <p>
 * This vulnerability allowed attackers to bypass ECDSA signature verification by using all-zero
 * signatures. The library defends against it with an explicit {@code r,s} component-range check in
 * {@code TokenSignatureValidator} (H3), independent of the underlying JCA provider.
 * <p>
 * Each test configures the issuer with the <em>matching</em> EC public key under the same {@code kid}
 * used to sign the token, so the tampered all-zero signature actually reaches the signature verifier.
 * The rejection is therefore asserted as {@code SIGNATURE_VALIDATION_FAILED} — the verifier rejecting
 * the degenerate signature — rather than {@code UNSUPPORTED_ALGORITHM}, which would mean the attack was
 * short-circuited against a mismatched (RSA) key before ever exercising the psychic-signature defense.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests for ECDSA Psychic Signature Attack Protection")
class PsychicSignatureAttackTest {

    @Test
    @DisplayName("Should reject an ES256 all-zero signature at the verifier with SIGNATURE_VALIDATION_FAILED")
    void shouldRejectTokenWithES256ZeroSignature() {
        // ES256 signature is 64 bytes (32 bytes for r, 32 bytes for s)
        assertZeroEcdsaSignatureReachesAndFailsVerifier(InMemoryKeyMaterialHandler.Algorithm.ES256, 64);
    }

    @Test
    @DisplayName("Should reject an ES384 all-zero signature at the verifier with SIGNATURE_VALIDATION_FAILED")
    void shouldRejectTokenWithES384ZeroSignature() {
        // ES384 signature is 96 bytes (48 bytes for r, 48 bytes for s)
        assertZeroEcdsaSignatureReachesAndFailsVerifier(InMemoryKeyMaterialHandler.Algorithm.ES384, 96);
    }

    @Test
    @DisplayName("Should reject an ES512 all-zero signature at the verifier with SIGNATURE_VALIDATION_FAILED")
    void shouldRejectTokenWithES512ZeroSignature() {
        // ES512 signature is 132 bytes (66 bytes for r, 66 bytes for s)
        assertZeroEcdsaSignatureReachesAndFailsVerifier(InMemoryKeyMaterialHandler.Algorithm.ES512, 132);
    }

    /**
     * Signs a token with the given EC algorithm, configures the issuer with the matching EC JWKS under
     * the same {@code kid}, tampers the signature to all zeros, and asserts the verifier rejects it.
     *
     * @param algorithm       the EC signing algorithm (ES256/ES384/ES512)
     * @param signatureLength the fixed-width JWS {@code r || s} signature length in bytes for the curve
     */
    private void assertZeroEcdsaSignatureReachesAndFailsVerifier(
            InMemoryKeyMaterialHandler.Algorithm algorithm, int signatureLength) {

        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next()
                .withSigningAlgorithm(algorithm);
        IssuerConfig issuerConfig = tokenHolder.getIssuerConfig();

        // TokenValidator is Closeable and schedules a background cache-eviction task; close it on every
        // path (including assertion failure) so the 3 invocations of this helper do not leak daemon threads.
        try (TokenValidator tokenValidator = TokenValidator.builder()
                     .parserConfig(ParserConfig.builder().build())
                     .issuerConfig(issuerConfig)
                     .build()) {

            String[] parts = tokenHolder.getRawToken().split("\\.");
            byte[] zeroSignature = new byte[signatureLength];
            String zeroSignatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(zeroSignature);
            String tamperedToken = parts[0] + "." + parts[1] + "." + zeroSignatureBase64;
            AccessTokenRequest request = AccessTokenRequest.of(tamperedToken);

            assertThrows(TokenValidationException.class, () -> tokenValidator.createAccessToken(request));

            SecurityEventCounter counter = tokenValidator.getSecurityEventCounter();
            assertAll("Psychic signature must be rejected by the signature verifier",
                    () -> assertEquals(1, counter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED),
                            "All-zero ECDSA signature must be rejected with SIGNATURE_VALIDATION_FAILED"),
                    () -> assertEquals(0, counter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM),
                            "Attack must reach the verifier, not be short-circuited as UNSUPPORTED_ALGORITHM"));
        }
    }
}
