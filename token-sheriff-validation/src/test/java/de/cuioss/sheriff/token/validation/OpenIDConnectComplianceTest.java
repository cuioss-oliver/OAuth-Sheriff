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

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests compliance with the OpenID Connect Core 1.0 specification.
 * This test class verifies that the library correctly implements the requirements
 * specified in OpenID Connect Core 1.0 for ID tokens.
 * 
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@EnableGeneratorController
@DisplayName("OpenID Connect Compliance Tests")
class OpenIDConnectComplianceTest {

    private static final String ISSUER = "Token-Test-testIssuer";

    private TokenValidator tokenValidator;
    private ValidationContext validationContext;

    @BeforeEach
    void setUp() {
        // Get the default JWKS content
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        // Create issuer config
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .algorithmPreferences(new SignatureAlgorithmPreferences())
                .build();

        // Create validation factory
        tokenValidator = TokenValidator.builder().issuerConfig(issuerConfig).build();

        // Initialize validation context
        validationContext = new ValidationContext(60, null);
    }

    @Nested
    @DisplayName("Section 2: ID Token")
    class IdTokenTests {

        @Test
        @DisplayName("2.2: Required Claims - 'iss' (Issuer) Claim")
        void shouldHandleIssuerClaim() {

            String token = TestTokenGenerators.idTokens().next().getRawToken();
            IdTokenContent result = tokenValidator.createIdToken(IdTokenRequest.of(token));
            assertEquals(ISSUER, result.getIssuer());
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("2.2: Required Claims - 'sub' (Subject) Claim")
        void shouldHandleSubjectClaim(TestTokenHolder tokenHolder) {

            String subject = "test-subject";

            // Set a specific subject
            tokenHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));

            // Since we explicitly set the subject claim, it should always be present
            // regardless of claimSubOptional configuration
            Optional<String> resultSubject = result.getSubject();
            assertTrue(resultSubject.isPresent(), "Subject should be present when explicitly set");
            assertEquals(subject, resultSubject.get());
        }

        @Test
        @DisplayName("2.2: Required Claims - 'aud' (Audience) Claim")
        void shouldHandleAudienceClaim() {

            String token = TestTokenGenerators.idTokens().next().getRawToken();
            IdTokenContent result = tokenValidator.createIdToken(IdTokenRequest.of(token));
            assertTrue(result.getAudience().contains(TestTokenHolder.TEST_AUDIENCE));
        }

        @Test
        @DisplayName("2.2: Required Claims - 'exp' (Expiration Time) Claim")
        void shouldHandleExpirationTimeClaim() {

            String token = TestTokenGenerators.idTokens().next().getRawToken();
            IdTokenContent result = tokenValidator.createIdToken(IdTokenRequest.of(token));
            assertNotNull(result.getExpirationDateTime());
            assertFalse(result.isExpired(validationContext));
        }

        @Test
        @DisplayName("2.2: Required Claims - 'iat' (Issued At) Claim")
        void shouldHandleIssuedAtClaim() {

            String token = TestTokenGenerators.idTokens().next().getRawToken();
            IdTokenContent result = tokenValidator.createIdToken(IdTokenRequest.of(token));
            assertNotNull(result.getIssuedAtDateTime());
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("2.2: Optional Claims - 'auth_time' (Authentication Time) Claim")
        void shouldHandleAuthTimeClaim(TestTokenHolder tokenHolder) {

            Instant authTime = Instant.now().minus(5, ChronoUnit.MINUTES);

            // Add auth_time claim
            tokenHolder.withClaim("auth_time", ClaimValue.forPlainString(String.valueOf(authTime.getEpochSecond())));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));
            assertTrue(result.getClaims().containsKey("auth_time"));
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("2.2: Optional Claims - 'nonce' Claim")
        void shouldHandleNonceClaim(TestTokenHolder tokenHolder) {

            String nonce = "test-nonce";

            // Add nonce claim
            tokenHolder.withClaim("nonce", ClaimValue.forPlainString(nonce));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));
            assertTrue(result.getClaims().containsKey("nonce"));
            assertEquals(nonce, result.getClaims().get("nonce").getOriginalString());
        }

        @Test
        @DisplayName("2.2: Optional Claims - 'azp' (Authorized Party) Claim")
        void shouldHandleAuthorizedPartyClaim() {

            String token = TestTokenGenerators.idTokens().next().getRawToken();
            IdTokenContent result = tokenValidator.createIdToken(IdTokenRequest.of(token));
            assertTrue(result.getClaimOption(ClaimName.AUTHORIZED_PARTY).isPresent());
            assertEquals(TestTokenHolder.TEST_CLIENT_ID, result.getClaimOption(ClaimName.AUTHORIZED_PARTY).get().getOriginalString());
        }
    }

    @Nested
    @DisplayName("Section 5: Standard Claims")
    class StandardClaimsTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("5.1: Standard Claims - 'name' Claim")
        void shouldHandleNameClaim(TestTokenHolder tokenHolder) {

            String name = "Test User";

            // Add name claim
            tokenHolder.withClaim(ClaimName.NAME.getName(), ClaimValue.forPlainString(name));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));
            assertEquals(name, result.getDisplayName().orElse(null));
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("5.1: Standard Claims - 'email' Claim")
        void shouldHandleEmailClaim(TestTokenHolder tokenHolder) {

            String email = "test@example.com";

            // Add email claim
            tokenHolder.withClaim(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(email));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));
            assertEquals(email, result.getEmail().orElse(null));
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 5)
        @DisplayName("5.1: Standard Claims - 'preferred_username' Claim")
        void shouldHandlePreferredUsernameClaim(TestTokenHolder tokenHolder) {

            String preferredUsername = "testuser";

            // Add preferred_username claim
            tokenHolder.withClaim(ClaimName.PREFERRED_USERNAME.getName(), ClaimValue.forPlainString(preferredUsername));

            String token = tokenHolder.getRawToken();
            IdTokenContent result = TokenValidator.builder().issuerConfig(tokenHolder.getIssuerConfig()).build().createIdToken(IdTokenRequest.of(token));
            assertTrue(result.getClaimOption(ClaimName.PREFERRED_USERNAME).isPresent());
            assertEquals(preferredUsername, result.getClaimOption(ClaimName.PREFERRED_USERNAME).get().getOriginalString());
        }
    }
}
