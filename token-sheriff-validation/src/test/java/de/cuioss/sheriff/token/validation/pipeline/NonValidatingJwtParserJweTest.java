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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.JweTestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("NonValidatingJwtParser JWE Integration Tests")
class NonValidatingJwtParserJweTest {

    private static final String ISSUER = "https://test-issuer.example.com";
    private KeyPair rsaEncryptionKeyPair;
    private SecurityEventCounter counter;

    @BeforeEach
    void setUp() {
        rsaEncryptionKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        counter = new SecurityEventCounter();
    }

    @Nested
    @DisplayName("JWE Token Handling")
    class JweTokenHandling {

        @Test
        @DisplayName("Should decrypt JWE and return inner JWS as DecodedJwt")
        void shouldDecryptJweAndReturnInnerJws() {
            // Create JWE token
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", ISSUER, null);

            // Create parser with JWE config
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .jweDecryptionConfig(config)
                    .build();

            // Decode
            DecodedJwt decoded = parser.decode(jwe);

            assertNotNull(decoded);
            assertNotNull(decoded.header());
            assertNotNull(decoded.body());
            // The rawToken should be the original JWE string (for caching)
            assertEquals(jwe, decoded.rawToken());
            // The inner JWS header should have the signing algorithm
            assertEquals("RS256", decoded.header().alg());
            // Should have issuer from inner JWS
            assertTrue(decoded.getIssuer().isPresent());
            assertEquals(ISSUER, decoded.getIssuer().get());
        }

        @Test
        @DisplayName("Should throw when JWE received but no config")
        void shouldThrowWhenJweReceivedButNoConfig() {
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", ISSUER, null);

            // Parser without JWE config
            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .build();

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> parser.decode(jwe));
            assertEquals(SecurityEventCounter.EventType.JWE_DECRYPTION_NOT_CONFIGURED, ex.getEventType());
        }

        @Test
        @DisplayName("Should still parse JWS tokens normally when JWE is configured")
        void shouldStillParseJwsNormally() {
            // Create a regular JWS token
            String jws = JweTestTokenFactory.createSignedJws(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(), "RS256", ISSUER);

            // Create parser with JWE config (should not interfere with JWS)
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .jweDecryptionConfig(config)
                    .build();

            DecodedJwt decoded = parser.decode(jws);
            assertNotNull(decoded);
            assertEquals("RS256", decoded.header().alg());
            assertTrue(decoded.getIssuer().isPresent());
            assertEquals(ISSUER, decoded.getIssuer().get());
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should reject nested JWE (5-part inner content)")
        void shouldRejectNestedJwe() {
            // Create a JWE that wraps another JWE instead of a JWS
            // First create inner JWE
            String innerJwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", ISSUER, null);

            // Then wrap in outer JWE
            String outerJwe = JweTestTokenFactory.encryptAsJwe(
                    innerJwe, rsaEncryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .jweDecryptionConfig(config)
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> parser.decode(outerJwe));
        }

        @Test
        @DisplayName("Should reject 4-part tokens")
        void shouldReject4PartTokens() {
            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> parser.decode("a.b.c.d"));
        }

        @Test
        @DisplayName("Should reject 6-part tokens")
        void shouldReject6PartTokens() {
            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> parser.decode("a.b.c.d.e.f"));
        }

        @Test
        @DisplayName("Should reject 5-part token without enc field")
        void shouldReject5PartTokenWithoutEnc() {
            // Create a 5-part token with a header that has no 'enc' field
            String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String fakeToken = encodedHeader + ".b.c.d.e";

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .jweDecryptionConfig(config)
                    .build();

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> parser.decode(fakeToken));
            assertTrue(ex.getMessage().contains("enc"));
        }

        @Test
        @DisplayName("Should decrypt JWE with compression (zip=DEF)")
        void shouldDecryptJweWithCompression() {
            String jwe = JweTestTokenFactory.createCompressedJwe(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RSA-OAEP", "A256GCM", ISSUER);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .compressionEnabled(true)
                    .build();

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .jweDecryptionConfig(config)
                    .build();

            DecodedJwt decoded = parser.decode(jwe);
            assertNotNull(decoded);
            assertEquals("RS256", decoded.header().alg());
            assertTrue(decoded.getIssuer().isPresent());
            assertEquals(ISSUER, decoded.getIssuer().get());
        }

        @Test
        @DisplayName("Should track security events for JWE without config")
        void shouldTrackSecurityEventsForJweWithoutConfig() {
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", ISSUER, null);

            NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .build();

            assertThrows(TokenValidationException.class, () -> parser.decode(jwe));
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.JWE_DECRYPTION_NOT_CONFIGURED));
        }
    }
}
