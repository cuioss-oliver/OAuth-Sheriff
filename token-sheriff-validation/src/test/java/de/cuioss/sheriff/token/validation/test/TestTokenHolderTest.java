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

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("TestTokenHolder Tests")
class TestTokenHolderTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create with default parameters")
        void shouldCreateWithDefaultParameters() {

            var tokenType = TokenType.ACCESS_TOKEN;
            var claimControl = ClaimControlParameter.builder().build();
            var tokenHolder = new TestTokenHolder(tokenType, claimControl);
            assertEquals(tokenType, tokenHolder.getTokenType(), "Token type should match");
            assertNotNull(tokenHolder.getClaims(), "Claims should not be null");
            assertFalse(tokenHolder.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.ISSUER.getName()), "Should contain issuer claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()), "Should contain subject claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.EXPIRATION.getName()), "Should contain expiration claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.ISSUED_AT.getName()), "Should contain issued at claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TOKEN_ID.getName()), "Should contain token ID claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TYPE.getName()), "Should contain type claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SCOPE.getName()), "Should contain scope claim");
            assertTrue(tokenHolder.getClaims().containsKey("roles"), "Should contain roles claim");
        }

        @Test
        @DisplayName("Should create with missing claims")
        void shouldCreateWithMissingClaims() {

            var tokenType = TokenType.ACCESS_TOKEN;
            var claimControl = ClaimControlParameter.builder()
                    .missingIssuer(true)
                    .missingSubject(true)
                    .missingExpiration(true)
                    .missingIssuedAt(true)
                    .missingTokenType(true)
                    .missingScope(true)
                    .build();
            var tokenHolder = new TestTokenHolder(tokenType, claimControl);
            assertEquals(tokenType, tokenHolder.getTokenType(), "Token type should match");
            assertNotNull(tokenHolder.getClaims(), "Claims should not be null");
            assertFalse(tokenHolder.getClaims().isEmpty(), "Claims should not be empty");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.ISSUER.getName()), "Should not contain issuer claim");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()), "Should not contain subject claim");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.EXPIRATION.getName()), "Should not contain expiration claim");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.ISSUED_AT.getName()), "Should not contain issued at claim");
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TOKEN_ID.getName()), "Should contain token ID claim");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.TYPE.getName()), "Should not contain type claim");
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SCOPE.getName()), "Should not contain scope claim");
            assertTrue(tokenHolder.getClaims().containsKey("roles"), "Should contain roles claim");
        }
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should generate valid JWT token")
        void shouldGenerateValidJwtToken() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(rawToken, "Raw token should not be null");
            assertFalse(rawToken.isEmpty(), "Raw token should not be empty");

            // Verify token structure (header.payload.signature)
            String[] parts = rawToken.split("\\.");
            assertEquals(3, parts.length, "JWT should have 3 parts");

            // Verify token can be parsed by JWT library
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt, "JWT should not be null");
            assertNotNull(jwt.getPayload());
            assertEquals(tokenHolder.getIssuer(), jwt.getPayload().get(ClaimName.ISSUER.getName()));
            assertEquals("test-subject", jwt.getPayload().get(ClaimName.SUBJECT.getName()));
        }

        @Test
        @DisplayName("Should cache token and regenerate after mutation")
        void shouldCacheTokenAndRegenerateAfterMutation() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When - get token first time
            var firstToken = tokenHolder.getRawToken();

            // Then - get token second time (should be cached)
            var secondToken = tokenHolder.getRawToken();
            assertEquals(firstToken, secondToken, "Tokens should be equal");

            // When - mutate token
            tokenHolder.withClaim("custom-claim", ClaimValue.forPlainString("custom-value"));

            // Then - get token third time (should be regenerated)
            var thirdToken = tokenHolder.getRawToken();
            assertNotEquals(firstToken, thirdToken, "Tokens should not be equal");
        }
    }

    @Nested
    @DisplayName("Mutator Tests")
    class MutatorTests {

        @Test
        @DisplayName("Should add claim")
        void shouldAddClaim() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var claimName = "custom-claim";
            var claimValue = ClaimValue.forPlainString("custom-value");
            tokenHolder.withClaim(claimName, claimValue);
            assertTrue(tokenHolder.getClaims().containsKey(claimName), "Claims should contain added claim");
            assertEquals(claimValue, tokenHolder.getClaims().get(claimName), "Claim value should match expected");
        }

        @Test
        @DisplayName("Should remove claim")
        void shouldRemoveClaim() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var claimName = ClaimName.SUBJECT.getName();
            tokenHolder.withoutClaim(claimName);
            assertFalse(tokenHolder.getClaims().containsKey(claimName), "Claims should not contain removed claim");
        }

        @Test
        @DisplayName("Should replace all claims")
        void shouldReplaceAllClaims() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var newClaims = Map.of(
                    "claim1", ClaimValue.forPlainString("value1"),
                    "claim2", ClaimValue.forPlainString("value2")
            );
            tokenHolder.withClaims(newClaims);
            assertEquals(2, tokenHolder.getClaims().size(), "Should have exactly 2 claims");
            assertTrue(tokenHolder.getClaims().containsKey("claim1"), "Should contain claim1");
            assertTrue(tokenHolder.getClaims().containsKey("claim2"), "Should contain claim2");
        }

        @Test
        @DisplayName("Should regenerate claims")
        void shouldRegenerateClaims() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When - modify claims
            tokenHolder.withoutClaim(ClaimName.SUBJECT.getName());
            tokenHolder.withClaim("custom-claim", ClaimValue.forPlainString("custom-value"));

            // Then - verify claims are modified
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertTrue(tokenHolder.getClaims().containsKey("custom-claim"));

            // When - regenerate claims
            tokenHolder.regenerateClaims();

            // Then - verify claims are regenerated
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertFalse(tokenHolder.getClaims().containsKey("custom-claim"));
        }
    }

    @Nested
    @DisplayName("Token Type Tests")
    class TokenTypeTests {

        @Test
        @DisplayName("Should create ACCESS_TOKEN")
        void shouldCreateAccessToken() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var claims = tokenHolder.getClaims();
            assertEquals(TokenType.ACCESS_TOKEN, tokenHolder.getTokenType(), "Token type should be ACCESS_TOKEN");
            assertEquals("Bearer",
                    claims.get(ClaimName.TYPE.getName()).getOriginalString(), "Type claim should match ACCESS_TOKEN");
            assertTrue(claims.containsKey(ClaimName.SCOPE.getName()), "Should contain scope claim");
            assertTrue(claims.containsKey("roles"), "Should contain roles claim");
        }

        @Test
        @DisplayName("Should create ID_TOKEN")
        void shouldCreateIdToken() {

            var tokenHolder = new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.builder().build());
            var claims = tokenHolder.getClaims();
            assertEquals(TokenType.ID_TOKEN, tokenHolder.getTokenType());
            assertEquals("ID",
                    claims.get(ClaimName.TYPE.getName()).getOriginalString());
            assertTrue(claims.containsKey(ClaimName.AUDIENCE.getName()));
            assertTrue(claims.containsKey(ClaimName.EMAIL.getName()));
            assertTrue(claims.containsKey(ClaimName.NAME.getName()));
            assertTrue(claims.containsKey(ClaimName.PREFERRED_USERNAME.getName()));
        }

        @Test
        @DisplayName("Should create REFRESH_TOKEN")
        void shouldCreateRefreshToken() {

            var tokenHolder = new TestTokenHolder(TokenType.REFRESH_TOKEN, ClaimControlParameter.builder().build());
            var claims = tokenHolder.getClaims();
            assertEquals(TokenType.REFRESH_TOKEN, tokenHolder.getTokenType());
            assertEquals("Refresh",
                    claims.get(ClaimName.TYPE.getName()).getOriginalString());
        }
    }

    @Nested
    @DisplayName("DecodedJwt Conversion Tests")
    class DecodedJwtConversionTests {

        @Test
        @DisplayName("asDecodedJwt should convert TestTokenHolder to DecodedJwt")
        void asDecodedJwtShouldConvertTestTokenHolderToDecodedJwt() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var rawToken = tokenHolder.getRawToken();
            var decodedJwt = tokenHolder.asDecodedJwt();
            assertNotNull(decodedJwt, "DecodedJwt should not be null");

            // Verify raw token
            assertEquals(rawToken, decodedJwt.rawToken(), "Raw token should match");

            // Verify parts
            String[] parts = rawToken.split("\\.");
            assertArrayEquals(parts, decodedJwt.parts(), "Token parts should match");

            // Verify header
            assertNotNull(decodedJwt.header(), "Header should be present");
            assertEquals(tokenHolder.getKeyId(), decodedJwt.header().getKid().orElse(""), "Key ID should match");
            assertEquals(tokenHolder.getSigningAlgorithm().name(), decodedJwt.header().alg(), "Algorithm should match");

            // Verify body
            assertNotNull(decodedJwt.body(), "Body should be present");
            assertEquals(tokenHolder.getIssuer(), decodedJwt.body().getString(ClaimName.ISSUER.getName()).orElse(""), "Issuer should match");
            assertEquals("test-subject", decodedJwt.body().getString(ClaimName.SUBJECT.getName()).orElse(""), "Subject should match");

            // Verify signature
            assertNotNull(decodedJwt.signature(), "Signature should be present");

            // Verify convenience methods
            assertEquals(tokenHolder.getIssuer(), decodedJwt.getIssuer().orElse(null), "Issuer from convenience method should match");
            assertEquals(tokenHolder.getKeyId(), decodedJwt.getKid().orElse(null), "Key ID from convenience method should match");
            assertEquals(tokenHolder.getSigningAlgorithm().name(), decodedJwt.getAlg().orElse(null), "Algorithm from convenience method should match");
        }

        @Test
        @DisplayName("asDecodedJwt should handle custom claims and headers")
        void asDecodedJwtShouldHandleCustomClaimsAndHeaders() {

            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // Add custom claim
            String customClaimName = "custom-claim";
            String customClaimValue = "custom-value";
            tokenHolder.withClaim(customClaimName, ClaimValue.forPlainString(customClaimValue));

            // Use custom key ID
            String customKeyId = "custom-key-id";
            tokenHolder.withKeyId(customKeyId);
            var decodedJwt = tokenHolder.asDecodedJwt();
            assertNotNull(decodedJwt, "DecodedJwt should not be null");

            // Verify custom claim
            assertNotNull(decodedJwt.body(), "Body should be present");
            assertEquals(customClaimValue, decodedJwt.body().getString(customClaimName).orElse(""), "Custom claim should match");

            // Verify custom key ID
            assertNotNull(decodedJwt.header(), "Header should be present");
            assertEquals(customKeyId, decodedJwt.header().getKid().orElse(""), "Custom key ID should match");
            assertEquals(customKeyId, decodedJwt.getKid().orElse(null), "Custom key ID from convenience method should match");
        }
    }

    @Nested
    @DisplayName("Header and Audience Tests")
    class HeaderAndAudienceTests {

        @Test
        @DisplayName("Should expose generated key ID")
        void shouldExposeGeneratedKeyId() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var keyId = tokenHolder.getKeyId();
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(keyId, "Key ID should not be null");
            assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, keyId, "Key ID should match default");
            assertNotNull(rawToken, "Raw token should not be null");

            // Parse the token and verify the key ID in the header
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            InMemoryKeyMaterialHandler.Algorithm.RS256, keyId))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(keyId, jwt.getHeader().get("kid"));
        }

        @Test
        @DisplayName("Should expose generated signing algorithm")
        void shouldExposeGeneratedSigningAlgorithm() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var algorithm = tokenHolder.getSigningAlgorithm();
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(algorithm, "Algorithm should not be null");
            assertEquals(InMemoryKeyMaterialHandler.Algorithm.RS256, algorithm, "Algorithm should be RS256");
            assertNotNull(rawToken, "Raw token should not be null");

            // Parse the token and verify it was signed with the correct algorithm
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey(algorithm))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(algorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should allow changing key ID")
        void shouldAllowChangingKeyId() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var originalKeyId = tokenHolder.getKeyId();
            var newKeyId = "custom-key-id";
            tokenHolder.withKeyId(newKeyId);
            var updatedKeyId = tokenHolder.getKeyId();
            var rawToken = tokenHolder.getRawToken();
            assertNotEquals(originalKeyId, updatedKeyId);
            assertEquals(newKeyId, updatedKeyId, "Updated key ID should match");

            // Parse the token and verify the key ID in the header
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            InMemoryKeyMaterialHandler.Algorithm.RS256, newKeyId))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(newKeyId, jwt.getHeader().get("kid"));
        }

        @Test
        @DisplayName("Should allow changing signing algorithm")
        void shouldAllowChangingSigningAlgorithm() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var originalAlgorithm = tokenHolder.getSigningAlgorithm();
            var newAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS384;
            tokenHolder.withSigningAlgorithm(newAlgorithm);
            var updatedAlgorithm = tokenHolder.getSigningAlgorithm();
            var rawToken = tokenHolder.getRawToken();
            assertNotEquals(originalAlgorithm, updatedAlgorithm);
            assertEquals(newAlgorithm, updatedAlgorithm, "Updated algorithm should match");

            // Parse the token and verify it was signed with the correct algorithm
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            newAlgorithm, tokenHolder.getKeyId()))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(newAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should provide public key aligned with key ID and algorithm")
        void shouldProvidePublicKeyAlignedWithKeyIdAndAlgorithm() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var customKeyId = "custom-key-id-for-public-key";
            var customAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS512;
            tokenHolder.withKeyId(customKeyId).withSigningAlgorithm(customAlgorithm);
            var publicKey = tokenHolder.getPublicKey();
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(publicKey, "Public key should not be null");

            // Verify that the public key can be used to verify the token
            var jwt = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt, "JWT should not be null");
            assertEquals(customKeyId, jwt.getHeader().get("kid"));
            assertEquals(customAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should invalidate cached token when header attributes change")
        void shouldInvalidateCachedTokenWhenHeaderAttributesChange() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // When - get token first time
            var firstToken = tokenHolder.getRawToken();

            // Then - get token second time (should be cached)
            var secondToken = tokenHolder.getRawToken();
            assertEquals(firstToken, secondToken, "Tokens should be equal");

            // When - change key ID
            tokenHolder.withKeyId("new-key-id");

            // Then - get token third time (should be regenerated)
            var thirdToken = tokenHolder.getRawToken();
            assertNotEquals(firstToken, thirdToken, "Tokens should not be equal");

            // When - get token fourth time (should be cached again)
            var fourthToken = tokenHolder.getRawToken();
            assertEquals(thirdToken, fourthToken, "Tokens should be equal");

            // When - change signing algorithm
            tokenHolder.withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS384);

            // Then - get token fifth time (should be regenerated)
            var fifthToken = tokenHolder.getRawToken();
            assertNotEquals(thirdToken, fifthToken);
        }

        @Test
        @DisplayName("Should use custom audience")
        void shouldUseCustomAudience() {

            List<String> customAudience = List.of("custom-audience-1", "custom-audience-2");
            var claimControl = ClaimControlParameter.builder().build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // Set custom audience using the new method
            tokenHolder.withAudience(customAudience);
            var claims = tokenHolder.getClaims();
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(claims, "Claims should not be null");
            assertTrue(claims.containsKey(ClaimName.AUDIENCE.getName()));

            // Verify the audience claim using the new getter method
            var audience = tokenHolder.getAudience();
            assertEquals(new LinkedHashSet<>(customAudience), audience, "Audience should match custom value");

            // Parse the token and verify the audience claim in the JWT
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                    .build()
                    .parseSignedClaims(rawToken);

            // The audience might be a single string or a collection depending on how many values there are
            Object jwtAudience = jwt.getPayload().get(ClaimName.AUDIENCE.getName());
            if (customAudience.size() == 1) {
                assertEquals(customAudience.getFirst(), jwtAudience);
            } else {
                // Convert both to sets to compare values regardless of collection type
                assertInstanceOf(Collection.class, jwtAudience, "Audience should be a collection");
                @SuppressWarnings("unchecked") Collection<String> audienceCollection = (Collection<String>) jwtAudience;
                assertEquals(new HashSet<>(customAudience), new HashSet<>(audienceCollection));
            }
        }

        @Test
        @DisplayName("Should provide public key as JwksLoader")
        void shouldProvidePublicKeyAsLoader() {

            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var customKeyId = "custom-key-id-for-jwks-loader";
            var customAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS512;
            tokenHolder.withKeyId(customKeyId).withSigningAlgorithm(customAlgorithm);
            var jwksLoader = tokenHolder.getPublicKeyAsLoader();
            var rawToken = tokenHolder.getRawToken();
            assertNotNull(jwksLoader, "JWKS loader should not be null");

            // Verify that the JwksLoader contains the key with the expected ID
            var keyInfo = jwksLoader.getKeyInfo(customKeyId);
            assertTrue(keyInfo.isPresent(), "Key info should be present for key ID: " + customKeyId);

            // Verify that the key from the JwksLoader can be used to verify the token
            var jwt = Jwts.parser()
                    .verifyWith(keyInfo.get().key())
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt, "JWT should not be null");
            assertEquals(customKeyId, jwt.getHeader().get("kid"));
            assertEquals(customAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }
    }

    @Nested
    @DisplayName("AccessTokenContent Conversion Tests")
    class AccessTokenContentConversionTests {

        @Test
        @DisplayName("asAccessTokenContent should convert ACCESS_TOKEN to AccessTokenContent")
        void asAccessTokenContentShouldConvertAccessTokenToAccessTokenContent() {
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var accessTokenContent = tokenHolder.asAccessTokenContent();

            assertNotNull(accessTokenContent, "AccessTokenContent should not be null");
            assertEquals(TokenType.ACCESS_TOKEN, accessTokenContent.getTokenType(), "Token type should be ACCESS_TOKEN");
            assertEquals(tokenHolder.getRawToken(), accessTokenContent.getRawToken(), "Raw token should match");

            // Verify claims are accessible
            assertNotNull(accessTokenContent.getScopes(), "Scopes should be accessible");
            assertNotNull(accessTokenContent.getRoles(), "Roles should be accessible");
            assertNotNull(accessTokenContent.getGroups(), "Groups should be accessible");
            assertFalse(accessTokenContent.getAudience().isEmpty(), "Audience should be present");
        }

        @Test
        @DisplayName("asAccessTokenContent should extract email from claims")
        void asAccessTokenContentShouldExtractEmailFromClaims() {
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            String testEmail = "test@example.com";

            // Add email claim
            tokenHolder.withClaim(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(testEmail));

            var accessTokenContent = tokenHolder.asAccessTokenContent();
            assertTrue(accessTokenContent.getEmail().isPresent(), "Email should be present");
            assertEquals(testEmail, accessTokenContent.getEmail().get(), "Email should match expected value");
        }

        @Test
        @DisplayName("asAccessTokenContent should handle missing email claim")
        void asAccessTokenContentShouldHandleMissingEmailClaim() {
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // Remove email claim if present
            tokenHolder.withoutClaim(ClaimName.EMAIL.getName());

            var accessTokenContent = tokenHolder.asAccessTokenContent();
            assertFalse(accessTokenContent.getEmail().isPresent(), "Email should not be present");
        }

        @Test
        @DisplayName("asAccessTokenContent should throw IllegalStateException for ID_TOKEN")
        void asAccessTokenContentShouldThrowIllegalStateExceptionForIdToken() {
            var tokenHolder = new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.builder().build());

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    tokenHolder::asAccessTokenContent,
                    "Should throw IllegalStateException for ID_TOKEN");

            assertTrue(exception.getMessage().contains("ID_TOKEN"),
                    "Exception message should mention ID_TOKEN");
            assertTrue(exception.getMessage().contains("ACCESS_TOKEN"),
                    "Exception message should mention ACCESS_TOKEN");
        }

        @Test
        @DisplayName("asAccessTokenContent should throw IllegalStateException for REFRESH_TOKEN")
        void asAccessTokenContentShouldThrowIllegalStateExceptionForRefreshToken() {
            var tokenHolder = new TestTokenHolder(TokenType.REFRESH_TOKEN, ClaimControlParameter.builder().build());

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    tokenHolder::asAccessTokenContent,
                    "Should throw IllegalStateException for REFRESH_TOKEN");

            assertTrue(exception.getMessage().contains("REFRESH_TOKEN"),
                    "Exception message should mention REFRESH_TOKEN");
            assertTrue(exception.getMessage().contains("ACCESS_TOKEN"),
                    "Exception message should mention ACCESS_TOKEN");
        }

        @Test
        @DisplayName("asAccessTokenContent should preserve all claims")
        void asAccessTokenContentShouldPreserveAllClaims() {
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // Add custom claims
            tokenHolder.withClaim("custom-claim", ClaimValue.forPlainString("custom-value"));
            tokenHolder.withClaim("another-claim", ClaimValue.forPlainString("another-value"));

            var accessTokenContent = tokenHolder.asAccessTokenContent();

            // Verify all claims are preserved
            assertEquals(tokenHolder.getClaims().size(), accessTokenContent.getClaims().size(),
                    "All claims should be preserved");

            for (Map.Entry<String, ClaimValue> entry : tokenHolder.getClaims().entrySet()) {
                assertTrue(accessTokenContent.getClaims().containsKey(entry.getKey()),
                        "Claim " + entry.getKey() + " should be preserved");
                assertEquals(entry.getValue(), accessTokenContent.getClaims().get(entry.getKey()),
                        "Claim value for " + entry.getKey() + " should match");
            }
        }
    }
}
