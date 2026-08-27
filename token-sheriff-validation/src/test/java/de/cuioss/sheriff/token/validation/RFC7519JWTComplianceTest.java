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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.JwtTokenTamperingUtil;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests compliance with the JWT specification defined in RFC 7519.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1">VALIDATION-1: Token Parsing and Validation</a> (RFC 7519 compliance)</li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.1">VALIDATION-1.1: Token Structure</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-2.1">VALIDATION-2.1: Base Token Functionality</a> (Standard JWT Claims)</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 */
@EnableGeneratorController
@DisplayName("RFC 7519 JWT Compliance Tests")
class RFC7519JWTComplianceTest {
    // No longer need a tokenValidator field as we'll create it on demand using tokenHolder.getIssuerConfig()
    private final ValidationContext validationContext = new ValidationContext(60, null);

    @Nested
    @DisplayName("Section 4.1: Registered Claim Names")
    class RegisteredClaimNamesTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.1: 'iss' (Issuer) Claim")
        void shouldHandleIssuerClaim(TestTokenHolder tokenHolder) {

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertEquals(TestTokenHolder.TEST_ISSUER, result.getIssuer());
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.2: 'sub' (Subject) Claim")
        void shouldHandleSubjectClaim(TestTokenHolder tokenHolder) {

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));

            assertNotNull(result, "Token should be parsed successfully");

            // Subject claim is mandatory per RFC 7519
            Optional<String> subject = result.getSubject();
            assertTrue(subject.isPresent(), "Subject must be present according to RFC 7519");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.3: 'aud' (Audience) Claim")
        void shouldHandleAudienceClaim(TestTokenHolder tokenHolder) {

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertFalse(result.getAudience().isEmpty());
            assertTrue(result.getAudience().contains(TestTokenHolder.TEST_AUDIENCE));
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.4: 'exp' (Expiration Time) Claim")
        void shouldHandleExpirationTimeClaim(TestTokenHolder tokenHolder) {

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertNotNull(result.getExpirationDateTime());
            assertFalse(result.isExpired(validationContext));
        }

        @Test
        @DisplayName("4.1.5: 'nbf' (Not Before) Claim")
        void shouldHandleNotBeforeClaim() {

            Instant notBefore = Instant.now().minus(5, ChronoUnit.MINUTES);
            OffsetDateTime notBeforeDateTime = OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Add the notBefore claim
            tokenHolder.withClaim(ClaimName.NOT_BEFORE.getName(),
                    ClaimValue.forDateTime(String.valueOf(notBeforeDateTime.toEpochSecond()), notBeforeDateTime));

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertTrue(result.getNotBeforeDateTime().isPresent());
        }

        @Test
        @DisplayName("4.1.6: 'iat' (Issued At) Claim")
        void shouldHandleIssuedAtClaim() {

            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertNotNull(result.getIssuedAtDateTime());
        }

        @Test
        @DisplayName("4.1.7: 'jti' (JWT ID) Claim")
        void shouldHandleJwtIdClaim() {

            String jwtId = "test-jwt-id";

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set a specific JWT ID
            tokenHolder.withClaim(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString(jwtId));

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            assertTrue(result.getClaimOption(ClaimName.TOKEN_ID).isPresent());
            assertEquals(jwtId, result.getClaimOption(ClaimName.TOKEN_ID).get().getOriginalString());
        }
    }

    @Nested
    @DisplayName("Section 3: JWT Format and Processing Rules")
    class JwtFormatAndProcessingTests {

        @Test
        @DisplayName("3.1: JWT Format - Three-part structure")
        void shouldHandleThreePartStructure() {

            String token = TestTokenGenerators.accessTokens().next().getRawToken();
            String[] parts = token.split("\\.");
            assertEquals(3, parts.length);
        }

        @Test
        @DisplayName("3.1: JWT Format - Base64URL encoding")
        void shouldHandleBase64UrlEncoding() {

            String token = TestTokenGenerators.accessTokens().next().getRawToken();
            String[] parts = token.split("\\.");
            // Verify that each part is Base64URL encoded (no padding, no invalid characters)
            for (String part : parts) {
                assertFalse(part.contains("+"));
                assertFalse(part.contains("/"));
                assertFalse(part.contains("="));
            }
        }

        @Test
        @DisplayName("3.2: JWT Header - 'alg' and 'typ' claims")
        void shouldHandleHeaderClaims() {

            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");
            // Note: The TokenContent interface doesn't provide direct access to header claims
            // This is tested indirectly by the fact that the token is successfully validated
        }
    }

    @Nested
    @DisplayName("Section 7.2: Token Validation")
    class TokenValidationTests {

        @Test
        @DisplayName("7.2: Validate signature")
        void shouldValidateSignature() {

            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result);
        }

        @Test
        @DisplayName("7.2: Reject validation with invalid signature")
        void shouldRejectInvalidSignature() {
            // Create a valid token first using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String validToken = tokenHolder.getRawToken();

            // Tamper with the signature using JwtTokenTamperingUtil
            String invalidToken = JwtTokenTamperingUtil.applyTamperingStrategy(
                    validToken,
                    JwtTokenTamperingUtil.TamperingStrategy.MODIFY_SIGNATURE_LAST_CHAR
            );
            TokenValidator validator = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build();
            var invalidSignatureRequest = AccessTokenRequest.of(invalidToken);
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(invalidSignatureRequest));

            assertEquals(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED, exception.getEventType());
        }

        @Test
        @DisplayName("7.2: Validate expiration time")
        void shouldValidateExpirationTime() {

            Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
            OffsetDateTime expiredDateTime = OffsetDateTime.ofInstant(expiredTime, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set expired expiration time
            tokenHolder.withClaim(ClaimName.EXPIRATION.getName(),
                    ClaimValue.forDateTime(String.valueOf(expiredDateTime.toEpochSecond()), expiredDateTime));

            String token = tokenHolder.getRawToken();
            TokenValidator validator = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build();
            var expiredRequest = AccessTokenRequest.of(token);
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(expiredRequest));

            assertEquals(SecurityEventCounter.EventType.TOKEN_EXPIRED, exception.getEventType());
        }

        @Test
        @DisplayName("7.2: Validate not before time")
        void shouldValidateNotBeforeTime() {

            Instant futureTime = Instant.now().plus(1, ChronoUnit.HOURS);
            OffsetDateTime futureDateTime = OffsetDateTime.ofInstant(futureTime, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set future not-before time
            tokenHolder.withClaim(ClaimName.NOT_BEFORE.getName(),
                    ClaimValue.forDateTime(String.valueOf(futureDateTime.toEpochSecond()), futureDateTime));

            String token = tokenHolder.getRawToken();
            TokenValidator validator = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build();
            var futureNbfRequest = AccessTokenRequest.of(token);
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(futureNbfRequest));

            assertEquals(SecurityEventCounter.EventType.TOKEN_NBF_FUTURE, exception.getEventType());
        }
    }

    @Nested
    @DisplayName("Section 5: JWT Claims Set")
    class JwtClaimsSetTests {

        @Test
        @DisplayName("5.1: JWT Claims Set - JSON object")
        void shouldHandleJsonClaimsSet() {

            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");

            // Verify that standard claims are accessible
            assertNotNull(result.getIssuer());

            // Subject claim is mandatory per RFC 7519
            Optional<String> subject = result.getSubject();
            assertTrue(subject.isPresent(), "Subject must be present according to RFC 7519");

            assertNotNull(result.getExpirationDateTime());
            assertNotNull(result.getIssuedAtDateTime());
        }

        @Test
        @DisplayName("5.2: JWT Claims Set - Custom claims")
        void shouldHandleCustomClaims() {

            String customClaimName = "custom_claim";
            String customClaimValue = "custom_value";

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Add custom claim
            tokenHolder.withClaim(customClaimName, ClaimValue.forPlainString(customClaimValue));

            String token = tokenHolder.getRawToken();
            AccessTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createAccessToken(AccessTokenRequest.of(token));
            assertNotNull(result, "Token should be parsed successfully");

            // Verify that custom claim is accessible
            assertTrue(result.getClaims().containsKey(customClaimName));
            assertEquals(customClaimValue, result.getClaims().get(customClaimName).getOriginalString());
        }
    }
}
