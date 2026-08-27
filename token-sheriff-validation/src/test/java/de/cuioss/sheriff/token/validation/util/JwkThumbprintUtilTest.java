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
package de.cuioss.sheriff.token.validation.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class JwkThumbprintUtilTest {

    private static final String EC_X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    private static final String EC_Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    private static final String OKP_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    /**
     * Test vector from RFC 7638 Section 3.1.
     * The example RSA key produces a known thumbprint.
     */
    @Test
    void shouldComputeRfc7638TestVector() {
        // RFC 7638 Section 3.1 test vector
        Map<String, Object> rsaJwk = Map.of(
                "kty", "RSA",
                "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e", "AQAB"
        );

        String thumbprint = JwkThumbprintUtil.computeThumbprint(rsaJwk);

        // Expected thumbprint from RFC 7638 Section 3.1
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint);
    }

    @Test
    void shouldComputeThumbprintForEcKey() {
        Map<String, Object> ecJwk = Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        );

        String thumbprint = JwkThumbprintUtil.computeThumbprint(ecJwk);

        assertNotNull(thumbprint);
        assertFalse(thumbprint.isEmpty());
        // Base64url without padding should not contain '='
        assertFalse(thumbprint.contains("="));
    }

    @Test
    void shouldComputeThumbprintForOkpKey() {
        Map<String, Object> okpJwk = Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", OKP_X
        );

        String thumbprint = JwkThumbprintUtil.computeThumbprint(okpJwk);

        assertNotNull(thumbprint);
        assertFalse(thumbprint.isEmpty());
        assertFalse(thumbprint.contains("="));
    }

    @Test
    void shouldProduceLexicographicOrdering() {
        // Verify that the same key with different map ordering produces the same thumbprint
        Map<String, Object> jwk1 = Map.of("kty", "RSA", "n", "abc", "e", "AQAB");
        Map<String, Object> jwk2 = Map.of("e", "AQAB", "n", "abc", "kty", "RSA");

        assertEquals(
                JwkThumbprintUtil.computeThumbprint(jwk1),
                JwkThumbprintUtil.computeThumbprint(jwk2)
        );
    }

    @Test
    void shouldEscapeJsonStringMembersPerRfc8259() {
        // A member value containing a quotation mark, reverse solidus and a control
        // character must be escaped in the canonical JSON per RFC 8259 (RFC 7638 Section 3).
        String rawCrv = "a\"b\\c\td";
        Map<String, Object> ecJwk = Map.of(
                "kty", "EC",
                "crv", rawCrv,
                "x", EC_X,
                "y", EC_Y
        );

        // Independently build the expected canonical JSON with the value escaped by hand.
        String escapedCrv = "a\\\"b\\\\c\\td";
        String canonicalJson = "{"
                + "\"crv\":\"" + escapedCrv + "\","
                + "\"kty\":\"EC\","
                + "\"x\":\"" + EC_X + "\","
                + "\"y\":\"" + EC_Y + "\"}";
        byte[] expectedHash = Sha256Util.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
        String expectedThumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedHash);

        assertEquals(expectedThumbprint, JwkThumbprintUtil.computeThumbprint(ecJwk),
                "Thumbprint must be computed over RFC 8259-escaped canonical JSON");
    }

    @Test
    void shouldRejectMissingKty() {
        Map<String, Object> jwk = Map.of("n", "abc", "e", "AQAB");

        assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.computeThumbprint(jwk));
    }

    @Test
    void shouldRejectUnsupportedKeyType() {
        Map<String, Object> jwk = Map.of("kty", "oct", "k", "abc");

        assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.computeThumbprint(jwk));
    }

    @Test
    void shouldRejectMissingRequiredRsaFields() {
        Map<String, Object> jwk = Map.of("kty", "RSA", "n", "abc");
        // Missing 'e'

        assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.computeThumbprint(jwk));
    }

    @Test
    void shouldRejectMissingRequiredEcFields() {
        Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256", "x", "abc");
        // Missing 'y'

        assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.computeThumbprint(jwk));
    }

    @Test
    void shouldIgnoreExtraFields() {
        // Extra fields should be ignored - thumbprint should only use required members
        Map<String, Object> jwkWithExtras = Map.of(
                "kty", "RSA",
                "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e", "AQAB",
                "kid", "extra-field",
                "alg", "RS256"
        );
        Map<String, Object> jwkMinimal = Map.of(
                "kty", "RSA",
                "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e", "AQAB"
        );

        assertEquals(
                JwkThumbprintUtil.computeThumbprint(jwkMinimal),
                JwkThumbprintUtil.computeThumbprint(jwkWithExtras)
        );
    }

    @Nested
    @DisplayName("Canonical JSON builder")
    class CanonicalJsonTests {

        @Test
        @DisplayName("Should emit e, kty, n in lexicographic order for an RSA key")
        void shouldEmitCanonicalMemberOrderForRsaKey() {
            Map<String, Object> rsaJwk = Map.of("kty", "RSA", "n", "abc", "e", "AQAB", "kid", "ignored");

            assertEquals("{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"abc\"}",
                    JwkThumbprintUtil.canonicalJson(rsaJwk));
        }

        @Test
        @DisplayName("Should emit crv, kty, x, y in lexicographic order for an EC key")
        void shouldEmitCanonicalMemberOrderForEcKey() {
            Map<String, Object> ecJwk = Map.of("kty", "EC", "crv", "P-256", "x", EC_X, "y", EC_Y, "kid", "ignored");

            assertEquals("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + EC_X + "\",\"y\":\"" + EC_Y + "\"}",
                    JwkThumbprintUtil.canonicalJson(ecJwk));
        }

        @Test
        @DisplayName("Should emit crv, kty, x in lexicographic order for an OKP key")
        void shouldEmitCanonicalMemberOrderForOkpKey() {
            Map<String, Object> okpJwk = Map.of("kty", "OKP", "crv", "Ed25519", "x", OKP_X, "kid", "ignored");

            assertEquals("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + OKP_X + "\"}",
                    JwkThumbprintUtil.canonicalJson(okpJwk));
        }

        @Test
        @DisplayName("Should reject an unsupported key type")
        void shouldRejectUnsupportedKeyType() {
            Map<String, Object> jwk = Map.of("kty", "oct", "k", "abc");

            assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.canonicalJson(jwk));
        }

        @Test
        @DisplayName("Should reject a missing required member")
        void shouldRejectMissingRequiredMember() {
            Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256", "x", EC_X);
            // Missing 'y'

            assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.canonicalJson(jwk));
        }

        @Test
        @DisplayName("Should reject a missing kty")
        void shouldRejectMissingKty() {
            Map<String, Object> jwk = Map.of("n", "abc", "e", "AQAB");

            assertThrows(IllegalArgumentException.class, () -> JwkThumbprintUtil.canonicalJson(jwk));
        }

        @ParameterizedTest
        @MethodSource("delegationVectors")
        @DisplayName("Should pin computeThumbprint to the SHA-256 of canonicalJson")
        void shouldPinComputeThumbprintToCanonicalJson(Map<String, Object> jwk) {
            String canonicalJson = JwkThumbprintUtil.canonicalJson(jwk);
            byte[] expectedHash = Sha256Util.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            String expectedThumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedHash);

            assertEquals(expectedThumbprint, JwkThumbprintUtil.computeThumbprint(jwk),
                    "computeThumbprint must hash exactly the canonicalJson output so the two cannot drift");
        }

        static Stream<Map<String, Object>> delegationVectors() {
            return Stream.of(
                    Map.of("kty", "RSA", "n", "abc", "e", "AQAB"),
                    Map.of("kty", "EC", "crv", "P-256", "x", EC_X, "y", EC_Y),
                    Map.of("kty", "OKP", "crv", "Ed25519", "x", OKP_X));
        }
    }
}
