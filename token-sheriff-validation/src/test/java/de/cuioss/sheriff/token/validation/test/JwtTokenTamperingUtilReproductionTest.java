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

import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Regression test for {@link JwtTokenTamperingUtil} ensuring that
 * {@link JwtTokenTamperingUtil.TamperingStrategy#MODIFY_SIGNATURE_LAST_CHAR}
 * actually changes the decoded signature bytes, not just the base64url characters.
 * <p>
 * This test was created to reproduce and verify the fix for a CI failure in
 * {@code shouldRejectAccessTokenWithInvalidSignature[44]} caused by two compounding bugs:
 * <ol>
 *   <li>Modifying the last base64url character may not change decoded bytes due to padding bits
 *       (e.g., 'A' and 'B' both decode to the same byte at the last position of a 256-byte
 *       RS256 signature)</li>
 *   <li>{@code generateDifferentChar} with a 2-value generator could fail to produce a different
 *       character within 10 attempts</li>
 * </ol>
 */
@EnableGeneratorController
@DisplayName("JwtTokenTamperingUtil Regression Tests")
class JwtTokenTamperingUtilReproductionTest {

    /**
     * Creates a minimal valid JWT string with a controlled signature.
     */
    private static String createTokenWithSignature(String signature) {
        // Base64url-encoded header: alg=RS256, typ=JWT
        String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        // Base64url-encoded payload: sub=test, iss=test-issuer, exp=9999999999
        String payload = "eyJzdWIiOiJ0ZXN0IiwiaXNzIjoidGVzdC1pc3N1ZXIiLCJleHAiOjk5OTk5OTk5OTl9";
        return header + "." + payload + "." + signature;
    }

    /**
     * Creates a 342-char base64url signature (simulating RS256 / 256 bytes)
     * with the specified last character and middle character.
     */
    private static String createSignature(char lastChar, char middleChar) {
        char[] sig = new char[342];
        Arrays.fill(sig, 'a'); // fill with valid base64url
        sig[sig.length - 1] = lastChar;
        sig[sig.length / 2] = middleChar;
        return new String(sig);
    }

    /**
     * Tests all critical combinations of last/middle chars that previously triggered the bug.
     * <p>
     * The last character values 'A', 'B', 'Q', 'g', 'w' represent the four possible
     * significant-bit patterns for the trailing base64url character of a 256-byte signature.
     * Middle characters 'X' and 'Y' are the values from CHAR_GENERATOR_X_Y which could
     * cause generateDifferentChar to return the original character.
     */
    @ParameterizedTest(name = "last=''{0}'', middle=''{1}''")
    @CsvSource({
            "A, X",
            "A, Y",
            "B, X",
            "B, Y",
            "A, a",
            "B, a",
            "Q, X",
            "Q, Y",
            "g, X",
            "w, X"
    })
    @DisplayName("Tampered signature must decode to different bytes")
    void shouldChangeDecodedBytes(char lastChar, char middleChar) {
        String signature = createSignature(lastChar, middleChar);
        String token = createTokenWithSignature(signature);

        String tampered = JwtTokenTamperingUtil.applyTamperingStrategy(
                token, JwtTokenTamperingUtil.TamperingStrategy.MODIFY_SIGNATURE_LAST_CHAR);

        String originalSig = token.split("\\.")[2];
        String tamperedSig = tampered.split("\\.")[2];

        byte[] originalBytes = Base64.getUrlDecoder().decode(originalSig);
        byte[] tamperedBytes = Base64.getUrlDecoder().decode(tamperedSig);

        assertFalse(Arrays.equals(originalBytes, tamperedBytes),
                "Tampered signature must decode to different bytes. " +
                        "Last: '" + originalSig.charAt(originalSig.length() - 1) + "'->'" +
                        tamperedSig.charAt(tamperedSig.length() - 1) + "', " +
                        "Middle: '" + originalSig.charAt(originalSig.length() / 2) + "'->'" +
                        tamperedSig.charAt(tamperedSig.length() / 2) + "'");
    }

    @Test
    @DisplayName("Tampered real token signature must decode to different bytes")
    void shouldChangeDecodedBytesWithRealToken() {
        var tokenHolder = TestTokenGenerators.accessTokens().next();
        String token = tokenHolder.getRawToken();
        String originalSig = token.split("\\.")[2];

        String tampered = JwtTokenTamperingUtil.applyTamperingStrategy(
                token, JwtTokenTamperingUtil.TamperingStrategy.MODIFY_SIGNATURE_LAST_CHAR);
        String tamperedSig = tampered.split("\\.")[2];

        byte[] originalBytes = Base64.getUrlDecoder().decode(originalSig);
        byte[] tamperedBytes = Base64.getUrlDecoder().decode(tamperedSig);

        assertFalse(Arrays.equals(originalBytes, tamperedBytes),
                "Tampered signature must decode to different bytes");
    }
}
