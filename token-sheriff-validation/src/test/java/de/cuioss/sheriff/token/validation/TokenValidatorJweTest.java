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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.sheriff.token.validation.test.JweTestTokenFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests for JWE decryption through {@link TokenValidator}.
 * <p>
 * Verifies that JWE-wrapped tokens (5-part compact serialization) are transparently
 * decrypted and then validated through the full pipeline, producing the same result
 * as direct JWS validation.
 */
@EnableTestLogger
@DisplayName("TokenValidator JWE End-to-End Tests")
class TokenValidatorJweTest {

    private KeyPair encryptionKeyPair;
    private IssuerConfig issuerConfig;
    private JweDecryptionConfig jweConfig;

    @BeforeEach
    void setUp() {
        encryptionKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        jweConfig = JweDecryptionConfig.builder()
                .defaultDecryptionKey(encryptionKeyPair.getPrivate())
                .build();
    }

    @Nested
    @DisplayName("Access Token via JWE")
    class AccessTokenViaJwe {

        @Test
        @DisplayName("Should decrypt JWE and validate inner access token")
        void shouldDecryptAndValidateAccessToken() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            // Wrap the valid JWS in JWE
            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            var result = validator.createAccessToken(AccessTokenRequest.of(jweToken));

            assertNotNull(result);
            assertNotNull(result.getClaims());
            assertFalse(result.getClaims().isEmpty());
        }

        @Test
        @DisplayName("Should validate same token twice (cache integration)")
        void shouldValidateSameTokenTwice() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            var result1 = validator.createAccessToken(AccessTokenRequest.of(jweToken));
            var result2 = validator.createAccessToken(AccessTokenRequest.of(jweToken));

            assertNotNull(result1);
            assertNotNull(result2);
            // Both should produce valid results
            assertFalse(result1.getClaims().isEmpty());
            assertFalse(result2.getClaims().isEmpty());
        }

        @Test
        @DisplayName("Should reject JWE with wrong decryption key")
        void shouldRejectJweWithWrongKey() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            // Use a different key pair for decryption (wrong key)
            KeyPair wrongKeyPair = JweTestTokenFactory.generateRsaKeyPair();
            JweDecryptionConfig wrongConfig = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(wrongKeyPair.getPrivate())
                    .build();

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(wrongConfig)
                    .build();

            var accessTokenRequest = AccessTokenRequest.of(jweToken);
            assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(accessTokenRequest));
        }
    }

    @Nested
    @DisplayName("ID Token via JWE")
    class IdTokenViaJwe {

        @Test
        @DisplayName("Should decrypt JWE and validate inner ID token")
        void shouldDecryptAndValidateIdToken() {
            TestTokenHolder tokenHolder = TestTokenGenerators.idTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            var result = validator.createIdToken(IdTokenRequest.of(jweToken));

            assertNotNull(result);
            assertNotNull(result.getClaims());
            assertFalse(result.getClaims().isEmpty());
        }
    }

    @Nested
    @DisplayName("JWS Coexistence")
    class JwsCoexistence {

        @Test
        @DisplayName("Should still validate regular JWS when JWE config is present")
        void shouldValidateJwsWithJweConfigPresent() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            // Pass raw JWS (3-part) — should work normally
            var result = validator.createAccessToken(AccessTokenRequest.of(rawJws));

            assertNotNull(result);
            assertFalse(result.getClaims().isEmpty());
        }
    }

    @Nested
    @DisplayName("Algorithm Variants")
    class AlgorithmVariants {

        @Test
        @DisplayName("Should decrypt RSA-OAEP-256 + A128GCM")
        void shouldDecryptRsaOaep256A128Gcm() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP-256", "A128GCM", null);

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            var result = validator.createAccessToken(AccessTokenRequest.of(jweToken));

            assertNotNull(result);
            assertFalse(result.getClaims().isEmpty());
        }

        @Test
        @DisplayName("Should decrypt RSA-OAEP + A128CBC-HS256")
        void shouldDecryptRsaOaepA128CbcHs256() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A128CBC-HS256", null);

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(jweConfig)
                    .build();

            var result = validator.createAccessToken(AccessTokenRequest.of(jweToken));

            assertNotNull(result);
            assertFalse(result.getClaims().isEmpty());
        }
    }

    @Nested
    @DisplayName("Security Events")
    class SecurityEvents {

        @Test
        @DisplayName("Should reject JWE when no decryption config")
        void shouldRejectJweWithoutConfig() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            // No JWE config
            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .build();

            var accessTokenRequest = AccessTokenRequest.of(jweToken);
            assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(accessTokenRequest));
        }

        @Test
        @DisplayName("Should track security events for JWE decryption failure")
        void shouldTrackSecurityEventsForDecryptionFailure() {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            issuerConfig = tokenHolder.getIssuerConfig();
            String rawJws = tokenHolder.getRawToken();

            String jweToken = JweTestTokenFactory.encryptAsJwe(
                    rawJws, encryptionKeyPair.getPublic(), "RSA-OAEP", "A256GCM", null);

            KeyPair wrongKeyPair = JweTestTokenFactory.generateRsaKeyPair();
            JweDecryptionConfig wrongConfig = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(wrongKeyPair.getPrivate())
                    .build();

            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .jweDecryptionConfig(wrongConfig)
                    .build();

            var accessTokenRequest = AccessTokenRequest.of(jweToken);
            assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(accessTokenRequest));

            // Security events should be tracked
            assertFalse(validator.getSecurityEventCounter().getCounters().isEmpty(),
                    "Security events should be tracked for decryption failure");
        }
    }
}
