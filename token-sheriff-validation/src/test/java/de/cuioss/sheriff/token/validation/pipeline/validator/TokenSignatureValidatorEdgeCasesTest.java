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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.jwks.JwksLoaderFactory;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for edge cases in {@link TokenSignatureValidator}.
 * <p>
 * This test class focuses on testing edge cases and error conditions
 * that might not be covered by the main test classes.
 */
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
@DisplayName("Tests TokenSignatureValidator Edge Cases")
class TokenSignatureValidatorEdgeCasesTest {

    private NonValidatingJwtParser jwtParser;
    private SecurityEventCounter securityEventCounter;
    private TokenSignatureValidator validator;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();

        jwtParser = NonValidatingJwtParser.builder().securityEventCounter(securityEventCounter).build();

        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));
    }

    @Test
    @DisplayName("Should reject token with missing signature")
    void shouldRejectTokenWithMissingSignature() {
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.INVALID_JWT_FORMAT);

        String token = createTokenWithoutSignature();

        // The parser should throw an exception when the token has an empty signature part
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> jwtParser.decode(token),
                "Should throw exception when signature is missing");

        assertEquals(SecurityEventCounter.EventType.INVALID_JWT_FORMAT, exception.getEventType(),
                "Exception should have INVALID_JWT_FORMAT event type");

        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.INVALID_JWT_FORMAT),
                "INVALID_JWT_FORMAT event should be incremented");
    }

    @Test
    @DisplayName("Should reject token with invalid format (not 3 parts)")
    void shouldRejectTokenWithInvalidFormat() {
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.INVALID_JWT_FORMAT);

        String token = createTokenWithInvalidFormat();

        // The parser should throw an exception when the token doesn't have exactly 3 parts
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> jwtParser.decode(token),
                "Should throw exception when token format is invalid");

        assertEquals(SecurityEventCounter.EventType.INVALID_JWT_FORMAT, exception.getEventType(),
                "Exception should have INVALID_JWT_FORMAT event type");

        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.INVALID_JWT_FORMAT),
                "INVALID_JWT_FORMAT event should be incremented");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when algorithm is missing (precondition violation)")
    void shouldRejectTokenWithMissingAlgorithm() {
        String token = createTokenWithoutAlgorithm();

        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Algorithm validation is now a precondition - should be validated by TokenHeaderValidator first
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> validator.validateSignature(decodedJwt),
                "Should throw IllegalStateException when algorithm precondition is violated");

        assertTrue(exception.getMessage().contains("Algorithm (alg) should have been validated by TokenHeaderValidator"),
                "Exception message should indicate precondition violation");
    }

    /**
     * Creates a token without a signature.
     */
    private String createTokenWithoutSignature() {
        // Create a valid token
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Return only the header and payload parts without the signature
        return parts[0] + "." + parts[1] + ".";
    }

    /**
     * Creates a token with invalid format (only 2 parts).
     */
    private String createTokenWithInvalidFormat() {
        // Create a valid token
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Return only the header and payload parts
        return parts[0] + "." + parts[1];
    }

    /**
     * Creates a token without an algorithm in the header.
     */
    private String createTokenWithoutAlgorithm() {
        // Create a valid token
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Modify the header to remove the alg
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        header = header.replaceAll("\"alg\":\"[^\"]*\",?", "");
        // Fix JSON if needed (remove trailing comma)
        header = header.replace(",}", "}");
        String modifiedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // Construct a token with the modified header but keep the original payload and signature
        return modifiedHeader + "." + parts[1] + "." + parts[2];
    }

    /**
     * Creates a token signed with RS256.
     */
    private String createToken() {
        // Create a token using TestTokenHolder
        var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));

        // Ensure the key ID is set to the default key ID
        tokenHolder.withKeyId(InMemoryJWKSFactory.DEFAULT_KEY_ID);

        // Return the raw token
        return tokenHolder.getRawToken();
    }
}
