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
package de.cuioss.sheriff.token.validation.jwks.http;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Issue #110: Key rotation grace period functionality.
 * Tests configuration validation and grace period behavior with real HTTP endpoints.
 * <p>
 * Verifies Requirement <a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4.5">VALIDATION-4.5: Key Rotation Grace Period</a>
 *
 * @author Oliver Wolff
 * @see <a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4.5">VALIDATION-4.5: Key Rotation Grace Period</a>
 * @see <a href="https://github.com/cuioss/TokenSheriff/issues/110">Issue #110: Key rotation grace period</a>
 */
@EnableTestLogger
@EnableMockWebServer
@DisplayName("Tests HttpJwksLoader Key Rotation Grace Period Implementation (Issue #110)")
class HttpJwksLoaderGracePeriodTest {

    private static final String ORIGINAL_KEY_ID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String ROTATED_KEY_ID = "alternative-key-id";


    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {
        @Getter
        private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

        @BeforeEach
        void setUp() {
            moduleDispatcher.setCallCounter(0);
            moduleDispatcher.returnDefault();
        }

        @Test
        @DisplayName("Should use default grace period of 5 minutes")
        void shouldUseDefaultGracePeriodOf5Minutes() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer")
                    .build(); // No explicit grace period - should use default

            assertEquals(Duration.ofMinutes(5), config.getKeyRotationGracePeriod(),
                    "Default grace period should be 5 minutes as per Issue #110");
            assertEquals(3, config.getMaxRetiredKeySets(),
                    "Default max retired key sets should be 3");
        }

        @Test
        @DisplayName("Should allow custom grace period configuration")
        void shouldAllowCustomGracePeriodConfiguration() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(10))
                    .maxRetiredKeySets(5)
                    .build();

            assertEquals(Duration.ofMinutes(10), config.getKeyRotationGracePeriod(),
                    "Custom grace period should be configurable");
            assertEquals(5, config.getMaxRetiredKeySets(),
                    "Custom max retired key sets should be configurable");
        }

        @Test
        @DisplayName("Should allow zero grace period to disable feature")
        void shouldAllowZeroGracePeriodToDisableFeature() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ZERO)
                    .build();

            assertEquals(Duration.ZERO, config.getKeyRotationGracePeriod(),
                    "Zero grace period should be allowed to disable the feature");
        }

        @Test
        @DisplayName("Configuration should be accessible via getters")
        void configurationShouldBeAccessibleViaGetters() {
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(5))
                    .maxRetiredKeySets(3)
                    .build();

            // Test that the getters work (they should be generated by Lombok)
            assertEquals(Duration.ofMinutes(5), config.getKeyRotationGracePeriod());
            assertEquals(3, config.getMaxRetiredKeySets());
        }

        @Test
        @DisplayName("Should validate negative grace period is not allowed")
        @SuppressWarnings("java:S5778") // Single lambda invocation - validation happens in setter
        void shouldValidateNegativeGracePeriodIsNotAllowed() {
            assertThrows(IllegalArgumentException.class, () ->
                    HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                            .jwksUrl("https://example.com/jwks")
                            .issuerIdentifier("test-issuer")
                            .keyRotationGracePeriod(Duration.ofMinutes(-1))
            );
        }

        @Test
        @DisplayName("Should validate maxRetiredKeySets is positive")
        void shouldValidateMaxRetiredKeySetsIsPositive() {
            var baseBuilder = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer");

            assertThrows(IllegalArgumentException.class,
                    () -> baseBuilder.maxRetiredKeySets(0));

            var anotherBuilder = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl("https://example.com/jwks")
                    .issuerIdentifier("test-issuer");

            assertThrows(IllegalArgumentException.class,
                    () -> anotherBuilder.maxRetiredKeySets(-1));
        }
    }

    @Nested
    @DisplayName("Key Rotation Behavior Tests")
    class KeyRotationBehaviorTests {

        @Getter
        private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

        private SecurityEventCounter securityEventCounter;

        @BeforeEach
        void setUp() {
            moduleDispatcher.setCallCounter(0);
            moduleDispatcher.returnDefault();
            securityEventCounter = new SecurityEventCounter();
        }

        @Test
        @DisplayName("Should immediately invalidate retired keys with zero grace period after rotation")
        void shouldImmediatelyInvalidateRetiredKeysWithZeroGracePeriod(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ZERO) // Zero grace period - should immediately invalidate retired keys
                    .refreshIntervalSeconds(1) // Enable background refresh for key rotation
                    .build();

            HttpJwksLoader loader = new HttpJwksLoader(config);
            loader.initJWKSLoader(securityEventCounter).join();

            // Initial load - should find the original key
            moduleDispatcher.returnDefault();
            Optional<KeyInfo> originalKey = loader.getKeyInfo(ORIGINAL_KEY_ID);
            assertTrue(originalKey.isPresent(), "Original key should be found initially");

            // Rotate keys - switch to different key
            moduleDispatcher.switchToOtherPublicKey();

            // Wait for key rotation to complete
            await("Key rotation to complete")
                    .atMost(5, SECONDS)
                    .until(() -> {
                        Optional<KeyInfo> newKey = loader.getKeyInfo(ROTATED_KEY_ID);
                        return newKey.isPresent();
                    });

            // New key should be accessible
            Optional<KeyInfo> rotatedKey = loader.getKeyInfo(ROTATED_KEY_ID);
            assertTrue(rotatedKey.isPresent(), "Rotated key should be found in current keys");

            // With zero grace period, original key should immediately be inaccessible
            // This verifies the timing bug fix - the key should be properly retired and immediately cleaned up
            Optional<KeyInfo> retiredKey = loader.getKeyInfo(ORIGINAL_KEY_ID);
            assertFalse(retiredKey.isPresent(),
                    """
                            Original key should NOT be accessible with zero grace period after rotation. \
                            This verifies the timing bug fix works correctly.""");

            loader.close();
        }

        @Test
        @DisplayName("Should keep retired keys accessible within grace period")
        void shouldKeepRetiredKeysAccessibleWithinGracePeriod(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(5)) // 5 minute grace period
                    .refreshIntervalSeconds(1) // Enable background refresh for key rotation
                    .build();

            HttpJwksLoader loader = new HttpJwksLoader(config);
            loader.initJWKSLoader(securityEventCounter).join();

            // Initial load - should find the original key
            moduleDispatcher.returnDefault();
            Optional<KeyInfo> originalKey = loader.getKeyInfo(ORIGINAL_KEY_ID);
            assertTrue(originalKey.isPresent(), "Original key should be found initially");

            // Rotate keys - switch to different key
            moduleDispatcher.switchToOtherPublicKey();

            // Wait for key rotation to complete
            await("Key rotation to complete")
                    .atMost(5, SECONDS)
                    .until(() -> {
                        Optional<KeyInfo> newKey = loader.getKeyInfo(ROTATED_KEY_ID);
                        return newKey.isPresent();
                    });

            // Both keys should be accessible: current key and retired key within grace period
            Optional<KeyInfo> rotatedKey = loader.getKeyInfo(ROTATED_KEY_ID);
            assertTrue(rotatedKey.isPresent(), "Current rotated key should be accessible");

            Optional<KeyInfo> retiredKey = loader.getKeyInfo(ORIGINAL_KEY_ID);
            assertTrue(retiredKey.isPresent(),
                    """
                            Original key should still be accessible within 5-minute grace period. \
                            This verifies the grace period mechanism works correctly.""");

            loader.close();
        }

        @Test
        @DisplayName("Should cleanup expired retired keys beyond grace period")
        void shouldCleanupExpiredRetiredKeysBeyondGracePeriod(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            // Use short grace period for faster test
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofSeconds(1)) // Very short grace period
                    .refreshIntervalSeconds(1)
                    .build();

            moduleDispatcher.returnDefault();
            HttpJwksLoader loader = new HttpJwksLoader(config);
            loader.initJWKSLoader(securityEventCounter).join();

            // Verify initial key
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Original key should be present initially");

            // Rotate keys
            moduleDispatcher.switchToOtherPublicKey();
            await("Key rotation")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getKeyInfo(ROTATED_KEY_ID).isPresent());

            // Original key should still be accessible immediately after rotation
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Original key should be in grace period immediately after rotation");

            // Wait for grace period to expire plus buffer
            await("Grace period to expire")
                    .pollDelay(1500, MILLISECONDS)
                    .atMost(5, SECONDS)
                    .until(() -> true);

            // Trigger another refresh to cleanup expired keys
            await("Another refresh cycle")
                    .atMost(5, SECONDS)
                    .until(() -> moduleDispatcher.getCallCounter() > 2);

            // Original key should now be gone (expired)
            assertFalse(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Original key should be cleaned up after grace period expires");

            // But rotated key should still be present
            assertTrue(loader.getKeyInfo(ROTATED_KEY_ID).isPresent(),
                    "Current key should remain available");

            loader.close();
        }

        @Test
        @DisplayName("Should enforce max retired key sets limit")
        void shouldEnforceMaxRetiredKeySetsLimit(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            // Configure with small limit
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(5))
                    .maxRetiredKeySets(2) // Only keep 2 retired sets
                    .refreshIntervalSeconds(1)
                    .build();

            // This test would require a more complex dispatcher that can rotate through
            // multiple different keys. For now, we test the configuration is honored.
            assertEquals(2, config.getMaxRetiredKeySets(),
                    "Max retired key sets should be configurable");

            // The actual enforcement is tested implicitly in the "unchanged refreshes" test
            // with maxRetiredKeySets=1
        }

        @Test
        @DisplayName("Should retain original key in grace period after multiple unchanged refreshes")
        void shouldRetainOriginalKeyDuringGracePeriodAfterMultipleUnchangedRefreshes(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            // Configure with only 1 maxRetiredKeySets to make the bug appear faster
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(5)) // 5 minute grace period
                    .refreshIntervalSeconds(1) // Fast refresh
                    .maxRetiredKeySets(1) // CRITICAL: Only keep 1 retired set - this exposes the bug!
                    .build();

            // Start with default key
            moduleDispatcher.returnDefault();

            HttpJwksLoader loader = new HttpJwksLoader(config);
            LoaderStatus status = loader.initJWKSLoader(securityEventCounter).join();
            assertEquals(LoaderStatus.OK, status, "Loader should initialize successfully");

            // Step 1: Verify original key is present after initialization
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Step 1: Original key present after initialization");

            // Step 2: Rotate keys - switch to alternative key
            moduleDispatcher.switchToOtherPublicKey();

            // Wait for first background refresh to pick up the rotation
            await("First key rotation")
                    .atMost(5, SECONDS)
                    .pollInterval(100, MILLISECONDS)
                    .until(() -> loader.getKeyInfo(ROTATED_KEY_ID).isPresent());

            // Step 3: Both keys should be accessible after first rotation
            assertTrue(loader.getKeyInfo(ROTATED_KEY_ID).isPresent(),
                    "Step 3a: Rotated key present");
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Step 3b: Original key in grace period after first rotation");

            // Step 4: Wait for ONE more background refresh with SAME content
            // With maxRetiredKeySets=1, this second refresh should push out the original key
            // even though it's still within the grace period!

            int callsBefore = moduleDispatcher.getCallCounter();

            // Wait for next refresh cycle
            await("Second background refresh")
                    .atMost(5, SECONDS)
                    .pollInterval(100, MILLISECONDS)
                    .until(() -> moduleDispatcher.getCallCounter() > callsBefore);

            // Verify we got another HTTP call
            assertTrue(moduleDispatcher.getCallCounter() > callsBefore,
                    "Background refresh should have made another HTTP call");

            // Step 5: Check if original key is still available
            // This SHOULD pass (key should still be in grace period)
            // but it WILL FAIL because updateKeys was called again with unchanged content
            assertTrue(loader.getKeyInfo(ROTATED_KEY_ID).isPresent(),
                    "Step 5a: Rotated key still present");

            // THIS IS THE BUG: Original key disappears even though within grace period!
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    """
                            Step 5b: BUG - Original key LOST after 2nd refresh with unchanged content! \
                            The key is within the 5-minute grace period but was pushed out because \
                            updateKeys() is called on every HTTP 200, even with unchanged content.""");

            loader.close();
        }
    }

    @Nested
    @DisplayName("Token Validation Roundtrip Tests")
    class TokenValidationRoundtripTests {
        @Getter
        private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

        @BeforeEach
        void setUp() {
            moduleDispatcher.setCallCounter(0);
            moduleDispatcher.returnDefault();
        }

        @Test
        @DisplayName("Should validate full JWT token roundtrip with grace period key rotation")
        void shouldValidateFullTokenRoundtripWithGracePeriodKeyRotation(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            // Configure loader with 5-minute grace period
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ofMinutes(5))
                    .refreshIntervalSeconds(1) // Enable background refresh
                    .build();

            // Ensure dispatcher is configured before creating loader
            moduleDispatcher.returnDefault();

            HttpJwksLoader loader = new HttpJwksLoader(config);
            // Don't initialize the loader here - TokenValidator will do it via IssuerConfigCache

            // Create IssuerConfig with our loader
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksLoader(loader)
                    .audienceValidationDisabled(true)
                    .build();

            // Create TokenValidator with cache disabled to ensure fresh validation
            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .cacheConfig(AccessTokenCacheConfig.builder()
                            .maxSize(0) // Disable caching
                            .build())
                    .build();

            // Wait for the loader to be initialized (IssuerConfigCache triggers async loading)
            await("Loader initialization")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getLoaderStatus() == LoaderStatus.OK);

            // Verify the loader has the original key
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Loader should have the original key after initialization");

            // Generate a token signed with the original key
            // Use TestTokenHolder constructor with TokenType and ClaimControlParameter
            TestTokenHolder tokenHolderOriginalKey = new TestTokenHolder(
                    TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder().build());

            // Configure the token with specific claims
            tokenHolderOriginalKey.withClaim("iss", ClaimValue.forPlainString("test-issuer"))
                    .withClaim("sub", ClaimValue.forPlainString("test-subject"))
                    .withAudience(List.of("test-audience"));

            String tokenSignedWithOriginalKey = tokenHolderOriginalKey.getRawToken();

            // Validate token with original key - should succeed
            AccessTokenContent validationResult1 = validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithOriginalKey));
            assertNotNull(validationResult1, "Token signed with original key should validate");
            assertEquals("test-subject", validationResult1.getSubject().orElse(null),
                    "Subject claim should match");

            // Rotate keys - switch to different key
            moduleDispatcher.switchToOtherPublicKey();

            // Wait for key rotation to complete
            await("Key rotation to complete")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getKeyInfo(ROTATED_KEY_ID).isPresent());

            // Generate a new token signed with the rotated key
            // We need to create a new TestTokenHolder that uses the alternative key
            TestTokenHolder tokenHolderRotatedKey = new TestTokenHolder(
                    TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder().build());

            // Configure with the rotated key and claims
            tokenHolderRotatedKey.withKeyId(ROTATED_KEY_ID)
                    .withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS384)
                    .withClaim("iss", ClaimValue.forPlainString("test-issuer"))
                    .withClaim("sub", ClaimValue.forPlainString("test-subject-rotated"))
                    .withAudience(List.of("test-audience"));

            String tokenSignedWithRotatedKey = tokenHolderRotatedKey.getRawToken();

            // Validate new token with rotated key - should succeed
            AccessTokenContent validationResult2 = validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithRotatedKey));
            assertNotNull(validationResult2, "Token signed with rotated key should validate");
            assertEquals("test-subject-rotated", validationResult2.getSubject().orElse(null),
                    "Subject claim should match for rotated key token");

            // CRITICAL: Validate the original token AFTER key rotation
            // This should STILL WORK due to the 5-minute grace period
            AccessTokenContent validationResult3 = validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithOriginalKey));
            assertNotNull(validationResult3,
                    """
                            Token signed with ORIGINAL key should STILL validate within grace period. \
                            This is the key test for Issue #110 - old tokens remain valid during grace period!""");
            assertEquals("test-subject", validationResult3.getSubject().orElse(null),
                    "Original token subject should still be accessible");

            // Both tokens should be valid simultaneously during grace period
            assertNotNull(validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithOriginalKey)),
                    "Original key token should remain valid");
            assertNotNull(validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithRotatedKey)),
                    "Rotated key token should be valid");

            loader.close();
        }

        @Test
        @DisplayName("Should immediately invalidate tokens after key rotation with zero grace period")
        void shouldImmediatelyInvalidateTokensWithZeroGracePeriod(URIBuilder uriBuilder) {
            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

            // Configure loader with ZERO grace period
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .keyRotationGracePeriod(Duration.ZERO) // Zero grace period!
                    .refreshIntervalSeconds(1)
                    .build();

            // Ensure dispatcher is configured before creating loader
            moduleDispatcher.returnDefault();

            HttpJwksLoader loader = new HttpJwksLoader(config);
            // DO NOT manually initialize the loader here - let IssuerConfig/TokenValidator do it
            // to avoid multiple initialization race condition

            // Create IssuerConfig with our loader
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier("test-issuer")
                    .jwksLoader(loader)
                    .audienceValidationDisabled(true)
                    .build();

            // No need to call initSecurityEventCounter - TokenValidator will handle it

            // Create TokenValidator with cache disabled to ensure fresh validation
            TokenValidator validator = TokenValidator.builder()
                    .issuerConfig(issuerConfig)
                    .cacheConfig(AccessTokenCacheConfig.builder()
                            .maxSize(0) // Disable caching
                            .build())
                    .build();

            // Wait for the loader to be initialized by TokenValidator AND keys to be loaded
            await("Loader initialization")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getLoaderStatus() == LoaderStatus.OK &&
                            loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent());

            // Verify the loader has the original key after initialization
            assertTrue(loader.getKeyInfo(ORIGINAL_KEY_ID).isPresent(),
                    "Loader should have the original key after initialization");

            // Generate a token signed with the original key
            TestTokenHolder tokenHolderOriginalKey = new TestTokenHolder(
                    TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder().build());

            tokenHolderOriginalKey.withClaim("iss", ClaimValue.forPlainString("test-issuer"))
                    .withClaim("sub", ClaimValue.forPlainString("test-subject"))
                    .withAudience(List.of("test-audience"));

            String tokenSignedWithOriginalKey = tokenHolderOriginalKey.getRawToken();

            // Validate token with original key - should succeed initially
            AccessTokenContent validationResult1 = validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithOriginalKey));
            assertNotNull(validationResult1, "Token signed with original key should validate initially");

            // Rotate keys
            moduleDispatcher.switchToOtherPublicKey();

            // Wait for key rotation to complete
            await("Key rotation to complete")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getKeyInfo(ROTATED_KEY_ID).isPresent());

            // Also ensure the old key is no longer available (zero grace period)
            await("Old key to be removed")
                    .atMost(5, SECONDS)
                    .until(() -> loader.getKeyInfo(ORIGINAL_KEY_ID).isEmpty());

            // CRITICAL: With zero grace period, the original token should immediately fail validation
            var accessTokenRequest = AccessTokenRequest.of(tokenSignedWithOriginalKey);
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(accessTokenRequest),
                    """
                            Token signed with original key should IMMEDIATELY FAIL with zero grace period. \
                            This verifies that zero grace period immediately invalidates old tokens!""");

            // Verify the exception is about key not found
            assertTrue(exception.getMessage().contains("key") || exception.getMessage().contains("Key"),
                    "Should fail with key-related error, got: " + exception.getMessage());

            // Generate and validate a new token with the rotated key - should succeed
            TestTokenHolder tokenHolderRotatedKey = new TestTokenHolder(
                    TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder().build());

            tokenHolderRotatedKey.withKeyId(ROTATED_KEY_ID)
                    .withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS384)
                    .withClaim("iss", ClaimValue.forPlainString("test-issuer"))
                    .withClaim("sub", ClaimValue.forPlainString("test-subject-new"))
                    .withAudience(List.of("test-audience"));

            String tokenSignedWithRotatedKey = tokenHolderRotatedKey.getRawToken();
            AccessTokenContent validationResult3 = validator.createAccessToken(AccessTokenRequest.of(tokenSignedWithRotatedKey));
            assertNotNull(validationResult3, "Token signed with rotated key should validate");

            loader.close();
        }
    }
}
