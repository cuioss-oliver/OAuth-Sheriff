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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("PkceChallenge S256 verifier/challenge pair (RFC 7636)")
class PkceChallengeTest {

    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    @DisplayName("Should always report the S256 method — the plain downgrade is never offered")
    void shouldAlwaysReportS256() {
        var challenge = PkceChallenge.generate();

        assertAll("method",
                () -> assertEquals("S256", challenge.method(), "method() is the S256 constant"),
                () -> assertEquals(PkceChallenge.METHOD_S256, challenge.method(), "method() equals the exported constant"));
    }

    @Test
    @DisplayName("Should derive the challenge as BASE64URL(SHA-256(verifier))")
    void shouldDeriveChallengeFromVerifier() throws Exception {
        var challenge = PkceChallenge.generate();

        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(challenge.codeVerifier().getBytes(StandardCharsets.US_ASCII));
        String expectedChallenge = BASE64_URL.encodeToString(digest);

        assertEquals(expectedChallenge, challenge.codeChallenge(),
                "code_challenge must be BASE64URL(SHA-256(code_verifier)) per RFC 7636 §4.2");
    }

    @Test
    @DisplayName("Should emit URL-safe, unpadded verifier and challenge")
    void shouldEmitUrlSafeValues() {
        var challenge = PkceChallenge.generate();

        assertAll("url-safe encoding",
                () -> assertFalse(challenge.codeVerifier().isBlank(), "verifier is non-blank"),
                () -> assertFalse(challenge.codeChallenge().isBlank(), "challenge is non-blank"),
                () -> assertTrue(challenge.codeVerifier().matches("[A-Za-z0-9_-]+"),
                        "verifier uses the URL-safe base64 alphabet without padding"),
                () -> assertTrue(challenge.codeChallenge().matches("[A-Za-z0-9_-]+"),
                        "challenge uses the URL-safe base64 alphabet without padding"));
    }

    @Test
    @DisplayName("Should generate a fresh high-entropy pair on every call")
    void shouldGenerateFreshPair() {
        var first = PkceChallenge.generate();
        var second = PkceChallenge.generate();

        assertAll("entropy",
                () -> assertNotEquals(first.codeVerifier(), second.codeVerifier(),
                        "each generation draws a fresh verifier"),
                () -> assertNotEquals(first.codeChallenge(), second.codeChallenge(),
                        "each generation yields a distinct challenge"));
    }

    @Test
    @DisplayName("Should honour the value-object equals/hashCode contract")
    void shouldHonourEqualsContract() {
        var challenge = PkceChallenge.generate();
        var other = PkceChallenge.generate();

        assertAll("equals/hashCode",
                () -> assertEquals(challenge, challenge, "a challenge equals itself"),
                () -> assertEquals(challenge.hashCode(), challenge.hashCode(), "hashCode is stable"),
                () -> assertNotEquals(challenge, other, "distinct pairs are not equal"),
                () -> assertNotEquals(null, challenge, "a challenge never equals null"),
                () -> assertNotEquals("S256", challenge, "a challenge never equals a foreign type"));
    }
}
