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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link InMemoryKeyMaterialHandler} and {@link InMemoryJWKSFactory} classes.
 */
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
@DisplayName("Tests for InMemoryKeyMaterialHandler and InMemoryJWKSFactory")
class InMemoryKeyHandlingTest {

    @Test
    @DisplayName("Should generate default keys for all algorithms")
    void shouldGenerateDefaultKeysForAllAlgorithms() {
        for (InMemoryKeyMaterialHandler.Algorithm algorithm : InMemoryKeyMaterialHandler.Algorithm.values()) {
            PrivateKey privateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(algorithm);
            PublicKey publicKey = InMemoryKeyMaterialHandler.getDefaultPublicKey(algorithm);

            assertNotNull(privateKey, "Private key should not be null for " + algorithm);
            assertNotNull(publicKey, "Public key should not be null for " + algorithm);

            String algName = algorithm.name();
            if (algName.startsWith("RS")) {
                assertEquals("RSA", privateKey.getAlgorithm(), "Private key should be RSA for " + algorithm);
                assertEquals("RSA", publicKey.getAlgorithm(), "Public key should be RSA for " + algorithm);
            } else if (algName.startsWith("PS")) {
                // PS algorithms use RSASSA-PSS keys
                assertEquals("RSASSA-PSS", privateKey.getAlgorithm(), "Private key should be RSASSA-PSS for " + algorithm);
                assertEquals("RSASSA-PSS", publicKey.getAlgorithm(), "Public key should be RSASSA-PSS for " + algorithm);
            } else if (algName.startsWith("ES")) {
                assertEquals("EC", privateKey.getAlgorithm(), "Private key should be EC for " + algorithm);
                assertEquals("EC", publicKey.getAlgorithm(), "Public key should be EC for " + algorithm);
            }
        }
    }

    @ParameterizedTest
    @EnumSource(InMemoryKeyMaterialHandler.Algorithm.class)
    @DisplayName("Should create valid JWKS for each algorithm")
    void shouldCreateValidJwksForEachAlgorithm(InMemoryKeyMaterialHandler.Algorithm algorithm) {
        String jwks = InMemoryKeyMaterialHandler.createDefaultJwks(algorithm);

        assertNotNull(jwks, "JWKS should not be null");
        assertTrue(jwks.contains("\"alg\":\"" + algorithm.getJwkAlgorithmName() + "\""), "JWKS should contain algorithm " + algorithm);

        // Parse the JWKS to verify it's valid JSON
        try (JsonReader reader = Json.createReader(new StringReader(jwks))) {
            JsonObject jwksObject = reader.readObject();
            assertTrue(jwksObject.containsKey("keys"), "JWKS should contain 'keys' array");
            assertEquals(1, jwksObject.getJsonArray("keys").size(), "JWKS should contain 1 key");

            JsonObject key = jwksObject.getJsonArray("keys").getJsonObject(0);
            String algName = algorithm.getJwkAlgorithmName();

            if (algName.startsWith("RS") || algName.startsWith("PS")) {
                assertEquals("RSA", key.getString("kty"), "Key type should be RSA for " + algorithm);
                assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, key.getString("kid"), "Key ID should match default");
                assertEquals(algorithm.getJwkAlgorithmName(), key.getString("alg"), "Algorithm should match");
                assertTrue(key.containsKey("n"), "RSA key should contain modulus");
                assertTrue(key.containsKey("e"), "RSA key should contain exponent");
            } else if (algName.startsWith("ES")) {
                assertEquals("EC", key.getString("kty"), "Key type should be EC for " + algorithm);
                assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, key.getString("kid"), "Key ID should match default");
                assertEquals(algorithm.getJwkAlgorithmName(), key.getString("alg"), "Algorithm should match");
                assertTrue(key.containsKey("crv"), "EC key should contain curve");
                assertTrue(key.containsKey("x"), "EC key should contain x coordinate");
                assertTrue(key.containsKey("y"), "EC key should contain y coordinate");

                // Verify the curve matches the algorithm
                String expectedCurve = switch (algName) {
                    case "ES256" -> "P-256";
                    case "ES384" -> "P-384";
                    case "ES512" -> "P-521";
                    default -> throw new IllegalArgumentException("Unsupported EC algorithm: " + algName);
                };
                assertEquals(expectedCurve, key.getString("crv"), "EC curve should match algorithm");
            }
        }
    }

    @Test
    @DisplayName("Should create multi-algorithm JWKS")
    void shouldCreateMultiAlgorithmJwks() {
        String jwks = InMemoryKeyMaterialHandler.createMultiAlgorithmJwks();

        assertNotNull(jwks, "JWKS should not be null");

        // Parse the JWKS to verify it's valid JSON
        try (JsonReader reader = Json.createReader(new StringReader(jwks))) {
            JsonObject jwksObject = reader.readObject();
            assertTrue(jwksObject.containsKey("keys"), "JWKS should contain 'keys' array");

            // Should have one key for each algorithm
            assertEquals(InMemoryKeyMaterialHandler.Algorithm.values().length,
                    jwksObject.getJsonArray("keys").size(),
                    "JWKS should contain one key for each algorithm");
        }
    }

    @Test
    @DisplayName("Should create JwksLoader with default key")
    void shouldCreateJwksLoaderWithDefaultKey() {
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        JwksLoader jwksLoader = InMemoryKeyMaterialHandler.createDefaultJwksLoader(securityEventCounter);

        assertNotNull(jwksLoader, "JwksLoader should not be null");

        // Verify the loader contains the default key
        Optional<KeyInfo> keyInfo = jwksLoader.getKeyInfo(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, keyInfo.get().keyId(), "Key ID should match");
        assertEquals("RS256", keyInfo.get().algorithm(), "Algorithm should be RS256");
        assertNotNull(keyInfo.get().key(), "Key should not be null");
    }

    @Test
    @DisplayName("Should create valid token with default key")
    void shouldCreateValidTokenWithDefaultKey() {
        // Create a token using TestTokenGenerators
        var tokenHolder = TestTokenGenerators.accessTokens().next();
        String token = tokenHolder.getRawToken();

        assertNotNull(token, "Token should not be null");

        // Verify the token can be parsed with the default public key
        var jws = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                .build()
                .parseSignedClaims(token);

        assertNotNull(jws, "JWS should not be null");
        assertEquals(tokenHolder.getSubject().orElse(null), jws.getPayload().getSubject(), "Subject should match");
        assertEquals(tokenHolder.getIssuer(), jws.getPayload().getIssuer(), "Issuer should match");
    }

    @ParameterizedTest
    @EnumSource(value = InMemoryKeyMaterialHandler.Algorithm.class, names = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
    @DisplayName("Should create valid token with RSA keys")
    void shouldCreateValidTokenWithRsaKeys(InMemoryKeyMaterialHandler.Algorithm algorithm) {
        // Create a token with the specified algorithm using TestTokenGenerators
        var tokenHolder = TestTokenGenerators.accessTokens().next().withSigningAlgorithm(algorithm);
        String token = tokenHolder.getRawToken();

        assertNotNull(token, "Token should not be null");

        // Verify the token can be parsed with the corresponding public key
        var jws = Jwts.parser()
                .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey(algorithm))
                .build()
                .parseSignedClaims(token);

        assertNotNull(jws, "JWS should not be null");
        assertEquals(tokenHolder.getSubject().orElse(null), jws.getPayload().getSubject(), "Subject should match");
        assertEquals(tokenHolder.getIssuer(), jws.getPayload().getIssuer(), "Issuer should match");
    }

    @Test
    @DisplayName("InMemoryJWKSFactory should create valid JWKS")
    void inMemoryJwksFactoryShouldCreateValidJwks() {
        String jwks = InMemoryJWKSFactory.createDefaultJwks();

        assertNotNull(jwks, "JWKS should not be null");
        assertTrue(jwks.contains("\"alg\":\"RS256\""), "JWKS should contain RS256 algorithm");

        // Parse the JWKS to verify it's valid JSON
        try (JsonReader reader = Json.createReader(new StringReader(jwks))) {
            JsonObject jwksObject = reader.readObject();
            assertTrue(jwksObject.containsKey("keys"), "JWKS should contain 'keys' array");
        }
    }

}
