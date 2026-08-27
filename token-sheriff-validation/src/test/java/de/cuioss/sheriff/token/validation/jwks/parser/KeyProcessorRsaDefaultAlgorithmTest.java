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
package de.cuioss.sheriff.token.validation.jwks.parser;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.Jwks;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.security.JwkAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests RSA key processing when the JWK does not specify an algorithm.
 * The KeyProcessor should default to RS256 and log a warning.
 */
@EnableTestLogger
@DisplayName("KeyProcessor RSA default algorithm")
class KeyProcessorRsaDefaultAlgorithmTest {

    private static final String TEST_KID = "test-rsa-no-alg";

    @Test
    @DisplayName("Should default to RS256 when RSA key has no algorithm specified")
    void shouldDefaultToRs256WhenNoAlgorithm() {
        var processor = new KeyProcessor(new SecurityEventCounter(), new JwkAlgorithmPreferences());

        // Derive n/e from the test infrastructure's default 2048-bit RSA key so the key satisfies the
        // >= 2048-bit minimum (M1) while still omitting "alg" — the scenario under test.
        RSAPublicKey defaultKey = (RSAPublicKey) InMemoryKeyMaterialHandler.getDefaultPublicKey();
        String rsaN = base64Url(toUnsignedBytes(defaultKey.getModulus()));
        String rsaE = base64Url(toUnsignedBytes(defaultKey.getPublicExponent()));

        // Create a JWKS JSON without "alg" for the RSA key
        String jwksJson = """
                {"keys":[{"kty":"RSA","use":"sig","kid":"%s","n":"%s","e":"%s"}]}"""
                .formatted(TEST_KID, rsaN, rsaE);

        // Parse via JwksParser to get JwkKey objects
        var dslJson = ParserConfig.builder().build().getDslJson();
        try {
            byte[] bytes = jwksJson.getBytes();
            var jwks = dslJson.deserialize(Jwks.class, bytes, bytes.length);

            var jwkKey = jwks.getKeys().orElseThrow().stream()
                    .filter(k -> TEST_KID.equals(k.getKid().orElse(null)))
                    .findFirst()
                    .orElseThrow();

            // Process — should succeed with RS256 default
            var result = processor.processKey(jwkKey);

            assertTrue(result.isPresent(), "RSA key without alg should be processed successfully");
            assertEquals("RS256", result.get().algorithm(), "Should default to RS256");
            assertEquals(TEST_KID, result.get().keyId());

            // Verify warning was logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "RS256");
        } catch (Exception e) {
            throw new AssertionError("Failed to parse test JWKS", e);
        }
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
