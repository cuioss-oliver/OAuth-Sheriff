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
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenHeaderValidator}.
 */
@EnableTestLogger(debug = TokenHeaderValidator.class, warn = TokenHeaderValidator.class)
@EnableGeneratorController
@DisplayName("Tests TokenHeaderValidator functionality")
class TokenHeaderValidatorTest {

    private static final SecurityEventCounter SECURITY_EVENT_COUNTER = new SecurityEventCounter();
    private static final NonValidatingJwtParser JWT_PARSER = NonValidatingJwtParser.builder()
            .securityEventCounter(SECURITY_EVENT_COUNTER)
            .build();

    // Helper method to create a TokenHeaderValidator with the shared SecurityEventCounter
    private TokenHeaderValidator createValidator(IssuerConfig issuerConfig) {
        return new TokenHeaderValidator(issuerConfig, SECURITY_EVENT_COUNTER);
    }

    @Nested
    @DisplayName("IssuerConfig Configuration Tests")
    class IssuerConfigConfigurationTests {

        @Test
        @DisplayName("Should create validator with expected issuer")
        void shouldCreateValidatorWithExpectedIssuer() {
            // Given an IssuerConfig with JWKS content
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();

            // When creating the validator
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // Then the validator should be created without warnings
            assertNotNull(validator);
            assertNotNull(issuerConfig.getAlgorithmPreferences());
        }

        @Test
        @DisplayName("Should create validator with custom algorithm preferences")
        void shouldCreateValidatorWithCustomAlgorithmPreferences() {
            // Given an IssuerConfig with custom algorithm preferences
            var customAlgorithmPreferences = new SignatureAlgorithmPreferences(List.of("RS256", "ES256"));
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .algorithmPreferences(customAlgorithmPreferences)
                    .audienceValidationDisabled(true)
                    .build();

            // When creating the validator
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // Then the validator should be created with the custom algorithm preferences
            assertNotNull(validator);
            assertSame(customAlgorithmPreferences, issuerConfig.getAlgorithmPreferences());
        }

    }

    @Nested
    @DisplayName("Algorithm Validation Tests")
    class AlgorithmValidationTests {

        @Test
        @DisplayName("Should validate validation with supported algorithm")
        void shouldValidateTokenWithSupportedAlgorithm() {
            // Given a validator with default algorithm preferences
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a supported algorithm (RS256)
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);

            // When validating the validation, it should not throw an exception
            assertDoesNotThrow(() -> validator.validate(decodedJwt, AccessTokenRequest.of("test")));
        }

        @Test
        @DisplayName("Should reject validation with unsupported algorithm")
        void shouldRejectTokenWithUnsupportedAlgorithm() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);

            // Given a validator with custom algorithm preferences that only support ES256
            var customAlgorithmPreferences = new SignatureAlgorithmPreferences(List.of("ES256"));
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .algorithmPreferences(customAlgorithmPreferences)
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with an unsupported algorithm (RS256)
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);
            assertEquals("RS256", decodedJwt.getAlg().orElse(null));

            // When validating the validation, it should throw an exception
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));
        }

        @Test
        @DisplayName("Should reject validation with missing algorithm")
        void shouldRejectTokenWithMissingAlgorithm() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a missing algorithm (manually created since generators always include alg)
            var emptyHeader = new JwtHeader(null, null, null, null, null, null, null, null, null, null);
            DecodedJwt decodedJwt = new DecodedJwt(emptyHeader, new MapRepresentation(Map.of()), null, new String[]{"", "", ""}, "");

            // When validating the validation, it should throw an exception
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: alg");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        }
    }

    @Nested
    @DisplayName("Key ID Validation Tests")
    class KeyIdValidationTests {

        @Test
        @DisplayName("Should reject token with missing key ID (kid)")
        void shouldRejectTokenWithMissingKeyId() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with a missing kid in the header
            var headerWithoutKid = new JwtHeader(
                    "RS256",  // alg
                    "JWT",    // typ
                    null,     // kid - missing
                    null,     // jwk
                    null,     // cty
                    null, null, null, null, null // JWE fields
            );

            // Create a DecodedJwt without kid
            DecodedJwt decodedJwt = new DecodedJwt(
                    headerWithoutKid,
                    new MapRepresentation(Map.of()),
                    "fake-signature",
                    new String[]{"header", "payload", "signature"},
                    "header.payload.signature"
            );

            // When validating the token, it should throw an exception
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());

            // And the exception message should mention kid
            assertTrue(exception.getMessage().contains("kid"));

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: kid");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        }

        @Test
        @DisplayName("Should reject token with missing kid and provide header info when typ is missing")
        void shouldRejectTokenWithMissingKidAndMissingTyp() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with missing kid and missing typ
            var headerWithoutKidAndTyp = new JwtHeader(
                    "RS256",  // alg
                    null,     // typ - missing
                    null,     // kid - missing
                    null,     // jwk
                    null,     // cty
                    null, null, null, null, null // JWE fields
            );

            // Create a DecodedJwt
            DecodedJwt decodedJwt = new DecodedJwt(
                    headerWithoutKidAndTyp,
                    new MapRepresentation(Map.of()),
                    "fake-signature",
                    new String[]{"header", "payload", "signature"},
                    "header.payload.signature"
            );

            // When validating the token, it should throw an exception
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception message includes available header info (only alg)
            assertTrue(exception.getMessage().contains("alg=RS256"));
        }

        @Test
        @DisplayName("Should reject token with missing kid and all other headers also missing")
        void shouldRejectTokenWithMissingKidAndAllHeadersMissing() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with ALL headers missing (including alg)
            var headerWithNothing = new JwtHeader(
                    null,     // alg - missing
                    null,     // typ - missing
                    null,     // kid - missing
                    null,     // jwk
                    null,     // cty
                    null, null, null, null, null // JWE fields
            );

            // Create a DecodedJwt
            DecodedJwt decodedJwt = new DecodedJwt(
                    headerWithNothing,
                    new MapRepresentation(Map.of()),
                    "fake-signature",
                    new String[]{"header", "payload", "signature"},
                    "header.payload.signature"
            );

            // When validating the token, it should throw an exception for missing alg first
            // (alg validation comes before kid validation)
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception is for missing alg (not kid, since alg is checked first)
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());
            assertTrue(exception.getMessage().contains("alg"));
        }
    }

    @Nested
    @DisplayName("Embedded JWK Protection Tests (CVE-2018-0114)")
    class EmbeddedJwkProtectionTests {

        // Test data: Complete valid RSA JWK for testing embedded JWK rejection
        private static final String EMBEDDED_RSA_JWK = """
                {
                  "kty": "RSA",
                  "n": "xGOr-H7A-PWG3z0hanVc22VWP",
                  "e": "AQAB",
                  "alg": "RS256",
                  "use": "sig"
                }""".replaceAll("\\s+", "");

        @Test
        @DisplayName("Should reject token with embedded JWK in header")
        void shouldRejectTokenWithEmbeddedJwk() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);

            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with an embedded JWK in the header
            // Create a JwtHeader with an embedded JWK
            var headerWithJwk = new JwtHeader(
                    "RS256",  // alg
                    "JWT",    // typ
                    "key-1",  // kid
                    EMBEDDED_RSA_JWK, // jwk - embedded JWK
                    null,     // cty
                    null, null, null, null, null // JWE fields
            );

            // Create a DecodedJwt with the header containing embedded JWK
            DecodedJwt decodedJwt = new DecodedJwt(
                    headerWithJwk,
                    new MapRepresentation(Map.of()),
                    "fake-signature",
                    new String[]{"header", "payload", "signature"},
                    "header.payload.signature"
            );

            // When validating the token, it should throw an exception
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM, exception.getEventType());

            // And the exception message should mention embedded JWK
            assertTrue(exception.getMessage().contains("Embedded JWK"));

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));
        }

        @Test
        @DisplayName("Should accept token without embedded JWK")
        void shouldAcceptTokenWithoutEmbeddedJwk() {
            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token without an embedded JWK in the header
            var headerWithoutJwk = new JwtHeader(
                    "RS256",  // alg
                    "JWT",    // typ
                    "key-1",  // kid
                    null,     // jwk - no embedded JWK
                    null,     // cty
                    null, null, null, null, null // JWE fields
            );

            // Create a DecodedJwt without embedded JWK
            DecodedJwt decodedJwt = new DecodedJwt(
                    headerWithoutJwk,
                    new MapRepresentation(Map.of()),
                    "fake-signature",
                    new String[]{"header", "payload", "signature"},
                    "header.payload.signature"
            );

            // When validating the token, it should not throw an exception for embedded JWK
            assertDoesNotThrow(() -> validator.validate(decodedJwt, AccessTokenRequest.of("test")));
        }
    }

    @Nested
    @DisplayName("Token Type Validation Tests (RFC 9068)")
    class TokenTypeValidationTests {

        @Test
        @DisplayName("Should accept token when no expected token type is configured")
        void shouldAcceptTokenWhenNoExpectedTokenTypeConfigured() {
            // Given a validator with token type validation disabled
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with typ: JWT
            var header = new JwtHeader(
                    "RS256", "JWT", "key-1",
                    null, null, null, null, null,
                    null, null
            );
            DecodedJwt decodedJwt = new DecodedJwt(
                    header, new MapRepresentation(Map.of()), "fake-signature",
                    new String[]{"header", "payload", "signature"}, "header.payload.signature"
            );

            // When validating, it should pass (no token type check)
            assertDoesNotThrow(() -> validator.validate(decodedJwt, AccessTokenRequest.of("test")));
        }

        @Test
        @DisplayName("Should accept token with matching token type")
        void shouldAcceptTokenWithMatchingTokenType() {
            // Given a validator with expectedTokenType="at+jwt"
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedTokenType("at+jwt")
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with typ: at+jwt
            var header = new JwtHeader(
                    "RS256", "at+jwt", "key-1",
                    null, null, null, null, null,
                    null, null
            );
            DecodedJwt decodedJwt = new DecodedJwt(
                    header, new MapRepresentation(Map.of()), "fake-signature",
                    new String[]{"header", "payload", "signature"}, "header.payload.signature"
            );

            // When validating, it should pass
            assertDoesNotThrow(() -> validator.validate(decodedJwt, AccessTokenRequest.of("test")));
        }

        @Test
        @DisplayName("Should accept token with matching token type (case-insensitive)")
        void shouldAcceptTokenWithMatchingTokenTypeCaseInsensitive() {
            // Given a validator with expectedTokenType="at+jwt"
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedTokenType("at+jwt")
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with typ: AT+JWT (uppercase)
            var header = new JwtHeader(
                    "RS256", "AT+JWT", "key-1",
                    null, null, null, null, null,
                    null, null
            );
            DecodedJwt decodedJwt = new DecodedJwt(
                    header, new MapRepresentation(Map.of()), "fake-signature",
                    new String[]{"header", "payload", "signature"}, "header.payload.signature"
            );

            // When validating, it should pass (case-insensitive comparison)
            assertDoesNotThrow(() -> validator.validate(decodedJwt, AccessTokenRequest.of("test")));
        }

        @Test
        @DisplayName("Should reject token with mismatched token type")
        void shouldRejectTokenWithMismatchedTokenType() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH);

            // Given a validator with expectedTokenType="at+jwt"
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedTokenType("at+jwt")
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with typ: JWT (mismatched)
            var header = new JwtHeader(
                    "RS256", "JWT", "key-1",
                    null, null, null, null, null,
                    null, null
            );
            DecodedJwt decodedJwt = new DecodedJwt(
                    header, new MapRepresentation(Map.of()), "fake-signature",
                    new String[]{"header", "payload", "signature"}, "header.payload.signature"
            );

            // When validating, it should throw TokenValidationException
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify exception details
            assertEquals(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH, exception.getEventType());
            assertTrue(exception.getMessage().contains("JWT"));
            assertTrue(exception.getMessage().contains("at+jwt"));

            // Verify warning was logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.TOKEN_TYPE_MISMATCH.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH));
        }

        @Test
        @DisplayName("Should reject token with missing token type when expected")
        void shouldRejectTokenWithMissingTokenType() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH);

            // Given a validator with expectedTokenType="at+jwt"
            var issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .expectedTokenType("at+jwt")
                    .audienceValidationDisabled(true)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a token with no typ header
            var header = new JwtHeader(
                    "RS256", null, "key-1",
                    null, null, null, null, null,
                    null, null
            );
            DecodedJwt decodedJwt = new DecodedJwt(
                    header, new MapRepresentation(Map.of()), "fake-signature",
                    new String[]{"header", "payload", "signature"}, "header.payload.signature"
            );

            // When validating, it should throw TokenValidationException
            var request = AccessTokenRequest.of("test");
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt, request));

            // Verify exception details
            assertEquals(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH, exception.getEventType());
            assertTrue(exception.getMessage().contains("(missing)"));
            assertTrue(exception.getMessage().contains("at+jwt"));

            // Verify warning was logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.TOKEN_TYPE_MISMATCH.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH));
        }
    }

}
