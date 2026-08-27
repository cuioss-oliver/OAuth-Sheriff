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

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.impl.CollectionGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenBuilder}.
 */
@EnableGeneratorController
@DisplayName("Tests TokenBuilder functionality")
class TokenBuilderTest {

    private TokenBuilder tokenBuilder;

    /**
     * Converts a JsonObject to MapRepresentation using DSL-JSON parsing.
     * This ensures proper DSL-JSON validation and type handling.
     */
    private static MapRepresentation convertJsonObjectToMapRepresentation(JsonObject jsonObject) {
        try {
            String json = jsonObject.toString();
            DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
            return MapRepresentation.fromJson(dslJson, json);
        } catch (IOException e) {
            throw new AssertionError("Failed to convert JsonObject to MapRepresentation", e);
        }
    }

    @BeforeEach
    void setUp() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier("test-issuer")
                .jwksContent("{\"keys\":[]}")
                .audienceValidationDisabled(true)
                .build();

        tokenBuilder = new TokenBuilder(issuerConfig);
    }

    @Nested
    @DisplayName("AccessToken Tests")
    class AccessTokenTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
        @DisplayName("createAccessToken should create AccessTokenContent from DecodedJwt")
        void createAccessTokenShouldCreateAccessTokenContent(TestTokenHolder tokenHolder) {
            DecodedJwt decodedJwt = tokenHolder.asDecodedJwt();

            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);
            assertTrue(result.isPresent(), "Should return AccessTokenContent");
            AccessTokenContent accessTokenContent = result.get();

            assertEquals(TokenType.ACCESS_TOKEN, accessTokenContent.getTokenType(), "Token type should be ACCESS_TOKEN");
            assertEquals(decodedJwt.rawToken(), accessTokenContent.getRawToken(), "Raw token should match");
            assertFalse(accessTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
        }

        @Test
        @DisplayName("createAccessToken should handle DecodedJwt with empty body")
        void createAccessTokenShouldHandleDecodedJwtWithEmptyBody() {
            var emptyHeader = new JwtHeader(null, null, null, null, null, null, null, null, null, null);
            DecodedJwt decodedJwt = new DecodedJwt(emptyHeader, new MapRepresentation(Map.of()), null, new String[]{"", "", ""}, "test-validation");

            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);
            assertTrue(result.isEmpty(), "Should return empty Optional when body is empty");
        }
    }

    @Nested
    @DisplayName("IdToken Tests")
    class IdTokenTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN, count = 2)
        @DisplayName("createIdToken should create IdTokenContent from DecodedJwt")
        void createIdTokenShouldCreateIdTokenContent(TestTokenHolder tokenHolder) {
            DecodedJwt decodedJwt = tokenHolder.asDecodedJwt();

            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);
            assertTrue(result.isPresent(), "Should return IdTokenContent");
            IdTokenContent idTokenContent = result.get();

            assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");
            assertEquals(decodedJwt.rawToken(), idTokenContent.getRawToken(), "Raw token should match");
            assertFalse(idTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.AUDIENCE.getName()),
                    "Claims should contain audience");
        }

        @Test
        @DisplayName("createIdToken should handle DecodedJwt with empty body")
        void createIdTokenShouldHandleDecodedJwtWithEmptyBody() {
            var emptyHeader = new JwtHeader(null, null, null, null, null, null, null, null, null, null);
            DecodedJwt decodedJwt = new DecodedJwt(emptyHeader, new MapRepresentation(Map.of()), null, new String[]{"", "", ""}, "test-validation");

            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);
            assertTrue(result.isEmpty(), "Should return empty Optional when body is empty");
        }
    }

    @Nested
    @DisplayName("RefreshToken Claims Tests")
    class RefreshTokenClaimsTests {

        @Test
        @DisplayName("extractClaimsForRefreshToken should extract claims from JsonObject")
        void extractClaimsForRefreshTokenShouldExtractClaims() {

            JsonObject jsonObject = Json.createObjectBuilder()
                    .add("sub", "test-subject")
                    .add("iss", "test-issuer")
                    .add("custom-claim", "custom-value")
                    .build();

            Map<String, ClaimValue> claims = TokenBuilder.extractClaimsForRefreshToken(convertJsonObjectToMapRepresentation(jsonObject));
            assertNotNull(claims, "Claims should not be null");
            assertFalse(claims.isEmpty(), "Claims should not be empty");
            assertEquals(3, claims.size(), "Should extract all claims");

            assertTrue(claims.containsKey("sub"), "Claims should contain subject");
            assertEquals("test-subject", claims.get("sub").getOriginalString(), "Subject claim value should match");

            assertTrue(claims.containsKey("iss"), "Claims should contain issuer");
            assertEquals("test-issuer", claims.get("iss").getOriginalString(), "Issuer claim value should match");

            assertTrue(claims.containsKey("custom-claim"), "Claims should contain custom claim");
            assertEquals("custom-value", claims.get("custom-claim").getOriginalString(), "Custom claim value should match");
        }

        @Test
        @DisplayName("extractClaimsForRefreshToken should handle empty JsonObject")
        void extractClaimsForRefreshTokenShouldHandleEmptyJsonObject() {
            JsonObject jsonObject = Json.createObjectBuilder().build();

            Map<String, ClaimValue> claims = TokenBuilder.extractClaimsForRefreshToken(convertJsonObjectToMapRepresentation(jsonObject));
            assertNotNull(claims, "Claims should not be null");
            assertTrue(claims.isEmpty(), "Claims should be empty");
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        private static final CuiLogger LOGGER = new CuiLogger(ThreadSafetyTests.class);
        private static final int CONCURRENT_THREADS = 8;

        @Test
        @DisplayName("TokenBuilder should be thread-safe under concurrent access")
        void shouldBeThreadSafeUnderConcurrentAccess() throws Exception {
            LOGGER.info("Verifying thread safety of TokenBuilder implementation");

            // Generate test tokens
            TypedGenerator<TestTokenHolder> generator = TestTokenGenerators.accessTokens();
            List<TestTokenHolder> tokenHolders = new CollectionGenerator<>(generator).list(100);
            List<DecodedJwt> testTokens = tokenHolders.stream()
                    .map(TestTokenHolder::asDecodedJwt)
                    .toList();

            final int concurrentIterations = 1000;
            final AtomicInteger errorCount = new AtomicInteger(0);
            final CountDownLatch startLatch = new CountDownLatch(1);
            final CountDownLatch completionLatch = new CountDownLatch(CONCURRENT_THREADS);

            ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_THREADS);

            try {
                for (int i = 0; i < CONCURRENT_THREADS; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();
                            // Each thread gets its own generator for thread-local random access
                            TypedGenerator<DecodedJwt> localGenerator = Generators.fixedValues(testTokens);

                            for (int j = 0; j < concurrentIterations; j++) {
                                DecodedJwt token = localGenerator.next();

                                try {
                                    Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(token);
                                    assertTrue(result.isPresent(), "Token should be created");

                                    // Verify basic claim presence
                                    AccessTokenContent accessToken = result.get();
                                    assertFalse(accessToken.getClaims().isEmpty(), "Claims should not be empty");
                                    assertTrue(accessToken.getClaims().containsKey("iss"), "Should contain issuer");
                                    assertTrue(accessToken.getClaims().containsKey("sub"), "Should contain subject");
                                } catch (IllegalArgumentException | IllegalStateException e) {
                                    LOGGER.error(e, "Error in concurrent test");
                                    errorCount.incrementAndGet();
                                }
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            completionLatch.countDown();
                        }
                    });
                }

                // Start all threads
                startLatch.countDown();

                // Wait for completion
                assertTrue(completionLatch.await(30, TimeUnit.SECONDS), "Concurrent test should complete");
                assertEquals(0, errorCount.get(), "No errors should occur during concurrent access");

            } finally {
                executor.shutdownNow();
            }

            LOGGER.info("Concurrent access verification completed successfully");
        }
    }

}
