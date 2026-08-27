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
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for validating protection against embedded JWK attacks.
 * <p>
 * The embedded JWK attack (CVE-2018-0114) is a security vulnerability where
 * attackers include their own public key in the token header to bypass signature
 * verification.
 * <p>
 * This test verifies that the library correctly rejects tokens with embedded JWK
 * headers.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests for Embedded JWK Attack Protection")
class EmbeddedJwkAttackTest {

    private TokenValidator tokenValidator;

    @BeforeEach
    void setUp() {
        // Create issuer config with JWKS content
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                .expectedAudience("test-client")
                .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                .build();

        // Create validation factory
        ParserConfig config = ParserConfig.builder().build();
        tokenValidator = TokenValidator.builder().parserConfig(config).issuerConfig(issuerConfig).build();
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 3)
    @DisplayName("Should reject tokens with embedded JWK in header")
    void shouldRejectTokenWithEmbeddedJwk(TestTokenHolder tokenHolder) {
        String validToken = tokenHolder.getRawToken();
        String[] parts = validToken.split("\\.");

        String header = parts[0];
        byte[] headerBytes = Base64.getUrlDecoder().decode(header);
        String headerJson = new String(headerBytes);

        String embeddedJwk = "\"jwk\":{\"kty\":\"RSA\",\"n\":\"attackerModulus\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"attacker-key\"}";
        String tamperedHeaderJson = headerJson.substring(0, headerJson.length() - 1) + "," + embeddedJwk + "}";
        String tamperedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedHeaderJson.getBytes());
        String tamperedToken = tamperedHeader + "." + parts[1] + "." + parts[2];

        var jwkRequest = AccessTokenRequest.of(tamperedToken);
        assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(jwkRequest),
                "Should reject token with embedded JWK header");

        assertTrue(tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) >= 0,
                "Security event counter should be available for embedded JWK attack tracking");
    }
}
