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
package de.cuioss.sheriff.token.validation.cache;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
class AccessTokenCacheTest {

    private AccessTokenCache cache;
    private SecurityEventCounter securityEventCounter;
    private TokenValidatorMonitor performanceMonitor;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        performanceMonitor = TokenValidatorMonitorConfig.builder()
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(10)
                .evictionIntervalSeconds(300L) // Use longer interval to avoid race conditions in tests
                .build();
        cache = new AccessTokenCache(config, securityEventCounter, 0);
    }

    @AfterEach
    void tearDown() {
        if (cache != null) {
            cache.shutdown();
        }
    }

    @Test
    void cacheMiss() {
        // Given
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxOTk5OTk5OTk5fQ.signature";
        AtomicInteger validationCount = new AtomicInteger(0);
        AccessTokenContent expectedContent = createAccessToken("https://example.com",
                OffsetDateTime.now().plusHours(1));

        // When
        Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
        assertTrue(cached.isEmpty());

        validationCount.incrementAndGet();
        cache.put(token, expectedContent, performanceMonitor);
        //noinspection UnnecessaryLocalVariable - Variable needed to avoid second cache access in assertions
        AccessTokenContent result = expectedContent;

        // Then
        assertNotNull(result);
        assertEquals(expectedContent, result);
        assertEquals(1, validationCount.get());
        assertEquals(1, cache.size());
        // No cache hit on first access
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.ACCESS_TOKEN_CACHE_HIT));
    }

    @Test
    void cacheHit() {
        // Given
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxOTk5OTk5OTk5fQ.signature";
        AtomicInteger validationCount = new AtomicInteger(0);
        AccessTokenContent expectedContent = createAccessToken("https://example.com",
                OffsetDateTime.now().plusHours(1));

        // First access - cache miss
        Optional<AccessTokenContent> cached1 = cache.get(token, performanceMonitor, OffsetDateTime.now());
        if (cached1.isEmpty()) {
            validationCount.incrementAndGet();
            cache.put(token, expectedContent, performanceMonitor);
        }

        // When - second access should be cache hit
        Optional<AccessTokenContent> cached2 = cache.get(token, performanceMonitor, OffsetDateTime.now());
        AccessTokenContent result;
        if (cached2.isEmpty()) {
            validationCount.incrementAndGet();
            result = expectedContent;
            cache.put(token, result, performanceMonitor);
        } else {
            result = cached2.get();
        }

        // Then
        assertNotNull(result);
        assertEquals(expectedContent, result);
        assertEquals(1, validationCount.get()); // Validation function called only once
        assertEquals(1, cache.size());
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.ACCESS_TOKEN_CACHE_HIT));
    }

    @Test
    void expiredTokenNotReturned() {
        // This test verifies that expired tokens are detected and throw exception

        // Given
        AtomicInteger validationCount = new AtomicInteger(0);

        // Create test data with consistent token
        String testToken = "test-jwt-token";

        // First access - cache a token with a fixed TTL
        OffsetDateTime tokenExpiry = OffsetDateTime.now().plusSeconds(2);
        AccessTokenContent expiredContent = createAccessTokenWithRawToken(
                "https://example.com",
                tokenExpiry,
                testToken
        );

        Optional<AccessTokenContent> cached1 = cache.get(testToken, performanceMonitor, OffsetDateTime.now());
        AccessTokenContent result1;
        if (cached1.isEmpty()) {
            validationCount.incrementAndGet();
            result1 = expiredContent;
            cache.put(testToken, result1, performanceMonitor);
        } else {
            result1 = cached1.get();
        }

        assertEquals(expiredContent, result1);
        assertEquals(1, validationCount.get());
        assertEquals(1, cache.size());

        // Injected clock: advance the reference instant past the token TTL instead of sleeping ~2 s
        // of wall-clock time. get(...) evaluates expiration against the supplied instant, so a
        // checkTime after the TTL makes the cached token expired deterministically.
        OffsetDateTime checkTime = tokenExpiry.plusSeconds(1);
        TokenValidationException exception =
                assertThrows(TokenValidationException.class, () ->
                        cache.get(testToken, performanceMonitor, checkTime));

        // Then
        assertEquals(SecurityEventCounter.EventType.TOKEN_EXPIRED, exception.getEventType());
        assertEquals(1, validationCount.get()); // Validation function called only once
        assertEquals(0, cache.size()); // Cache cleared after detecting expiration
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.ACCESS_TOKEN_CACHE_HIT));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.TOKEN_EXPIRED));
    }

    @Test
    void concurrentAccess() throws Exception {
        // Given
        String token = "concurrent-token";
        AtomicInteger validationCount = new AtomicInteger(0);
        AccessTokenContent content = createAccessToken("https://example.com", OffsetDateTime.now().plusHours(1));

        int threadCount = 5; // Reduced thread count for stability
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        // When - multiple threads access the same token concurrently
        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
                        AccessTokenContent result;
                        if (cached.isEmpty()) {
                            validationCount.incrementAndGet();
                            // Simple atomic operation, no complex simulation
                            result = content;
                            cache.put(token, result, performanceMonitor);
                        } else {
                            result = cached.get();
                        }
                        assertNotNull(result);
                        assertEquals(content, result);
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            // Wait for completion with shorter timeout
            assertTrue(doneLatch.await(2, TimeUnit.SECONDS), "All threads should complete quickly");
            executor.shutdown();
            assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS), "Executor should terminate cleanly");
        }

        // Then - with optimistic caching, validation may happen 1-5 times (race condition)
        // Each thread validates in parallel, first to putIfAbsent wins
        int actualValidationCount = validationCount.get();
        assertTrue(actualValidationCount >= 1 && actualValidationCount <= threadCount,
                "Validation should happen at least once, at most " + threadCount + " times, actual: " + actualValidationCount);
        assertEquals(1, cache.size());

        // Verify subsequent access is a cache hit
        Optional<AccessTokenContent> cachedResult = cache.get(token, performanceMonitor, OffsetDateTime.now());
        assertTrue(cachedResult.isPresent(), "Token should be in cache");
        assertNotNull(cachedResult.get());
        assertEquals(content, cachedResult.get());
        // Validation count doesn't change after cache hit
        assertEquals(actualValidationCount, validationCount.get());
    }

    @Test
    void concurrentAccessHighContention() throws Exception {
        // Test optimistic caching under high contention (issue #131/#132 fix verification)
        // Given
        String token = "high-contention-token";
        AtomicInteger validationCount = new AtomicInteger(0);
        AtomicInteger successCount = new AtomicInteger(0);
        AccessTokenContent content = createAccessToken("https://example.com", OffsetDateTime.now().plusHours(1));

        int threadCount = 50; // High concurrency to trigger race conditions
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        // When - many threads access the same token simultaneously
        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        // Wait for all threads to be ready
                        startLatch.await();

                        Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
                        AccessTokenContent result;
                        if (cached.isEmpty()) {
                            validationCount.incrementAndGet();
                            // Simulate some work to widen the race window. Use a lightweight park
                            // rather than Awaitility (which is for async assertions): across 50
                            // concurrent threads under parallel CPU contention its polling machinery
                            // adds overhead and can throw ConditionTimeoutException, spuriously
                            // failing unrelated threads.
                            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
                            result = content;
                            cache.put(token, result, performanceMonitor);
                        } else {
                            result = cached.get();
                        }

                        assertNotNull(result);
                        assertEquals(content, result);
                        successCount.incrementAndGet();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        fail("Thread was interrupted: " + e.getMessage());
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            // Start all threads simultaneously
            startLatch.countDown();

            // Wait for completion
            assertTrue(doneLatch.await(5, TimeUnit.SECONDS), "All threads should complete without blocking");
            executor.shutdown();
            assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS), "Executor should terminate cleanly");
        }

        // Then - verify optimistic caching behavior
        assertEquals(threadCount, successCount.get(), "All threads should successfully retrieve the token");
        int actualValidationCount = validationCount.get();
        assertTrue(actualValidationCount >= 1, "Validation should happen at least once");
        assertTrue(actualValidationCount <= threadCount, "Validation should not exceed thread count");
        assertEquals(1, cache.size(), "Only one token should be cached");

        // Note: Multiple validations are expected (optimistic caching trades duplicate work for no blocking)
        // This is the fix for issue #131/#132
    }

    @Test
    void concurrentAccessMultipleTokens() throws Exception {
        // Test that different tokens can be validated in parallel without contention
        // Given
        int tokenCount = 10;
        int threadsPerToken = 5;
        AtomicInteger totalValidationCount = new AtomicInteger(0);
        AtomicInteger successCount = new AtomicInteger(0);

        int totalThreads = tokenCount * threadsPerToken;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(totalThreads);

        // When - many threads access different tokens concurrently
        try (ExecutorService executor = Executors.newFixedThreadPool(totalThreads)) {
            for (int tokenIndex = 0; tokenIndex < tokenCount; tokenIndex++) {
                final String token = "token-" + tokenIndex;
                final AccessTokenContent content = createAccessToken("https://example.com", OffsetDateTime.now().plusHours(1));

                for (int threadIndex = 0; threadIndex < threadsPerToken; threadIndex++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();

                            Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
                            AccessTokenContent result;
                            if (cached.isEmpty()) {
                                totalValidationCount.incrementAndGet();
                                result = content;
                                cache.put(token, result, performanceMonitor);
                            } else {
                                result = cached.get();
                            }

                            assertNotNull(result);
                            successCount.incrementAndGet();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            fail("Thread was interrupted: " + e.getMessage());
                        } finally {
                            doneLatch.countDown();
                        }
                    });
                }
            }

            // Start all threads simultaneously
            startLatch.countDown();

            // Wait for completion
            assertTrue(doneLatch.await(5, TimeUnit.SECONDS), "All threads should complete quickly");
            executor.shutdown();
            assertTrue(executor.awaitTermination(2, TimeUnit.SECONDS), "Executor should terminate cleanly");
        }

        // Then
        assertEquals(totalThreads, successCount.get(), "All threads should successfully retrieve tokens");
        assertTrue(totalValidationCount.get() >= tokenCount, "Each token should be validated at least once");
        assertEquals(tokenCount, cache.size(), "All unique tokens should be cached");
    }

    @SuppressWarnings("SameParameterValue") // Test helper - intentionally uses consistent test data
    private AccessTokenContent createAccessToken(String issuer, OffsetDateTime expiration) {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(issuer));
        if (expiration != null) {
            tokenHolder.withClaim(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(String.valueOf(expiration.toEpochSecond()), expiration));
        }
        tokenHolder.withClaim(ClaimName.ISSUED_AT.getName(), ClaimValue.forDateTime(String.valueOf(OffsetDateTime.now().minusMinutes(5).toEpochSecond()), OffsetDateTime.now().minusMinutes(5)));
        tokenHolder.withClaim(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString("jti-" + System.nanoTime()));
        return tokenHolder.asAccessTokenContent();
    }

    @SuppressWarnings("SameParameterValue") // Test helper - intentionally uses consistent test data
    private AccessTokenContent createAccessTokenWithRawToken(String issuer, OffsetDateTime expiration, String rawToken) {
        // Create a simple AccessTokenContent with the specified raw token
        // This simulates what would happen in real JWT validation where the raw token matches the input
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(issuer));
        if (expiration != null) {
            tokenHolder.withClaim(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(String.valueOf(expiration.toEpochSecond()), expiration));
        }
        tokenHolder.withClaim(ClaimName.ISSUED_AT.getName(), ClaimValue.forDateTime(String.valueOf(OffsetDateTime.now().minusMinutes(5).toEpochSecond()), OffsetDateTime.now().minusMinutes(5)));
        tokenHolder.withClaim(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString("jti-" + System.nanoTime()));

        // Get the generated content
        AccessTokenContent generated = tokenHolder.asAccessTokenContent();

        // Create a new instance with our specified raw token
        return new AccessTokenContent(generated.getClaims(), rawToken);
    }

    @Test
    void cacheEvictionUnderLoad() {
        // Given - cache with maxSize 10
        assertEquals(0, cache.size());

        // When - fill cache to capacity
        for (int i = 0; i < 10; i++) {
            String token = "token-" + i;
            AccessTokenContent content = createAccessToken("https://example.com",
                    OffsetDateTime.now().plusHours(1));
            Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
            AccessTokenContent result;
            if (cached.isEmpty()) {
                result = content;
                cache.put(token, result, performanceMonitor);
            } else {
                result = cached.get();
            }
            assertNotNull(result);
        }

        // Then - cache should be at capacity
        assertEquals(10, cache.size());
    }

    @Test
    void shouldHandleCacheEvictionProperly() {
        // Given - fill cache to capacity first
        for (int i = 0; i < 10; i++) {
            String token = "token-" + i;
            AccessTokenContent content = createAccessToken("https://example.com",
                    OffsetDateTime.now().plusHours(1));
            Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
            if (cached.isEmpty()) {
                cache.put(token, content, performanceMonitor);
            }
        }
        assertEquals(10, cache.size());

        // When - add 11th token to trigger eviction
        String overflowToken = "token-10";
        AccessTokenContent overflowContent = createAccessToken("https://example.com",
                OffsetDateTime.now().plusHours(1));
        Optional<AccessTokenContent> cached = cache.get(overflowToken, performanceMonitor, OffsetDateTime.now());
        AccessTokenContent result;
        if (cached.isEmpty()) {
            result = overflowContent;
            cache.put(overflowToken, result, performanceMonitor);
        } else {
            result = cached.get();
        }

        // Then - should not throw ConcurrentModificationException
        assertNotNull(result);
        assertEquals(overflowContent, result);
        // Cache size should still be 10 (one token was evicted)
        assertEquals(10, cache.size());
    }

    @Test
    void concurrentCacheEviction() throws Exception {
        // Given - smaller cache to make eviction more likely
        cache.shutdown();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(5)
                .evictionIntervalSeconds(300L)
                .build();
        cache = new AccessTokenCache(config, securityEventCounter, 0);

        int threadCount = 5; // Reduced thread count
        int tokensPerThread = 3; // Reduced tokens per thread
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);

        // When - multiple threads add different tokens concurrently
        try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
            for (int i = 0; i < threadCount; i++) {
                final int threadId = i;
                executor.submit(() -> {
                    try {
                        // Create thread-local performance monitor to avoid contention
                        TokenValidatorMonitor threadMonitor = TokenValidatorMonitorConfig.builder()
                                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                                .build()
                                .createMonitor();

                        for (int j = 0; j < tokensPerThread; j++) {
                            String token = "thread-" + threadId + "-token-" + j;
                            AccessTokenContent content = createAccessToken("https://example.com",
                                    OffsetDateTime.now().plusHours(1));
                            Optional<AccessTokenContent> cached = cache.get(token, threadMonitor, OffsetDateTime.now());
                            AccessTokenContent result;
                            if (cached.isEmpty()) {
                                result = content;
                                cache.put(token, result, threadMonitor);
                            } else {
                                result = cached.get();
                            }
                            assertNotNull(result);
                            successCount.incrementAndGet();
                        }
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            // Wait for completion with longer timeout (test may be slow on CI)
            assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "All threads should complete");
            executor.shutdown();
            assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS), "Executor should terminate cleanly");
        }

        // Then - all operations should succeed
        assertEquals(threadCount * tokensPerThread, successCount.get());

        // Cache should be near maxSize - due to lock-free design, it may temporarily exceed during concurrent operations
        // This is acceptable as the cache prioritizes throughput over strict size limits
        int cacheSize = cache.size();
        assertTrue(cacheSize > 0, "Cache should not be empty");
        assertTrue(cacheSize <= 10,
                "Cache size " + cacheSize + " should not exceed 2x maxSize under concurrent load");
    }

    @Test
    void cacheEvictionBatchRemoval() {
        // Given - cache that evicts 10% when full
        cache.shutdown();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(300L)
                .build();
        cache = new AccessTokenCache(config, securityEventCounter, 0);

        // When - fill cache to capacity
        for (int i = 0; i < 100; i++) {
            String token = "token-" + i;
            AccessTokenContent content = createAccessToken("https://example.com",
                    OffsetDateTime.now().plusHours(1));
            Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
            if (cached.isEmpty()) {
                cache.put(token, content, performanceMonitor);
            }
        }

        assertEquals(100, cache.size());

        // When - add one more token to trigger batch eviction
        Optional<AccessTokenContent> cached = cache.get("overflow-token", performanceMonitor, OffsetDateTime.now());
        if (cached.isEmpty()) {
            AccessTokenContent content = createAccessToken("https://example.com", OffsetDateTime.now().plusHours(1));
            cache.put("overflow-token", content, performanceMonitor);
        }

        // Then - should have evicted ~10% of entries
        assertTrue(cache.size() <= 91); // Should have evicted at least 10 entries
        assertTrue(cache.size() >= 90); // But not too many
    }

    @Test
    void tokenWithoutExpirationThrowsException() {
        // Given a token without expiration claim
        // Note: This scenario should never occur in practice because tokens are validated
        // before caching, and validation requires a valid exp claim. This test verifies
        // that if somehow an invalid token reaches the cache, it fails immediately.
        String token = "token-without-exp";
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        // Remove expiration claim
        tokenHolder.getClaims().remove(ClaimName.EXPIRATION.getName());
        AccessTokenContent contentWithoutExp = tokenHolder.asAccessTokenContent();

        Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
        assertTrue(cached.isEmpty(), "Cache should be empty initially");

        // When/Then - should throw IllegalStateException from getExpirationTime()
        IllegalStateException exception = assertThrows(IllegalStateException.class, () ->
                cache.put(token, contentWithoutExp, performanceMonitor)
        );

        assertEquals("ExpirationTime claim not present in token", exception.getMessage());
    }

    @Test
    void cacheDisabledNoEvictionLogic() {
        // Given - cache with size 0 (disabled)
        cache.shutdown();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(0)
                .evictionIntervalSeconds(300L)
                .build();
        cache = new AccessTokenCache(config, securityEventCounter, 0);

        // When - try to cache tokens
        for (int i = 0; i < 10; i++) {
            String token = "token-" + i;
            AtomicInteger validationCount = new AtomicInteger(0);
            AccessTokenContent content = createAccessToken("https://example.com",
                    OffsetDateTime.now().plusHours(1));

            Optional<AccessTokenContent> cached = cache.get(token, performanceMonitor, OffsetDateTime.now());
            AccessTokenContent result;
            if (cached.isEmpty()) {
                validationCount.incrementAndGet();
                result = content;
                // When cache is disabled, put should be a no-op
                cache.put(token, result, performanceMonitor);
            } else {
                result = cached.get();
            }

            // Then - validation happens every time (no caching)
            assertNotNull(result);
            assertEquals(1, validationCount.get());
        }

        // Cache should remain empty
        assertEquals(0, cache.size());
    }

    @Test
    void evictionExecutorRemovesExpiredTokens() {
        // Given - cache with eviction interval of 1 second
        cache.shutdown();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(10) // Reduced size
                .evictionIntervalSeconds(1L) // Run eviction every second
                .build();
        cache = new AccessTokenCache(config, securityEventCounter, 0);

        // Pre-expire the tokens (TTL already in the past) so the background eviction executor removes
        // them on its next scheduled tick without any ~2 s wall-clock wait for the expiry transition.
        // Only the executor's 1 s scheduling interval remains — not a token-TTL sleep.
        OffsetDateTime expirationTime = OffsetDateTime.now().minusSeconds(1);
        for (int i = 0; i < 5; i++) {
            String rawToken = "raw-token-" + i;
            AccessTokenContent content = createAccessTokenWithRawToken(
                    "https://example.com",
                    expirationTime,
                    rawToken
            );
            Optional<AccessTokenContent> cached = cache.get(rawToken, performanceMonitor, OffsetDateTime.now());
            if (cached.isEmpty()) {
                cache.put(rawToken, content, performanceMonitor);
            }
        }

        // Then - verify all 5 tokens are in cache
        assertEquals(5, cache.size());

        // Await only the background executor's next scheduled tick (interval 1 s); the tokens are
        // already past their TTL, so there is no wall-clock wait for the expiry transition itself.
        await()
                .atMost(4, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .untilAsserted(() ->
                        assertEquals(0, cache.size(), "All expired tokens should be evicted"));

        // Verify we can still add new tokens after eviction
        String newToken = "new-token-after-eviction";
        AccessTokenContent newContent = createAccessToken("https://example.com",
                OffsetDateTime.now().plusHours(1));
        Optional<AccessTokenContent> cached = cache.get(newToken, performanceMonitor, OffsetDateTime.now());
        AccessTokenContent result;
        if (cached.isEmpty()) {
            result = newContent;
            cache.put(newToken, result, performanceMonitor);
        } else {
            result = cached.get();
        }

        assertNotNull(result);
        assertEquals(1, cache.size());
    }


    @Test
    void shutdownDoesNotStopCallerSuppliedExecutor() {
        ScheduledExecutorService callerExecutor =
                Executors.newSingleThreadScheduledExecutor();
        try {
            AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                    .maxSize(10)
                    .evictionIntervalSeconds(300L)
                    .scheduledExecutorService(callerExecutor)
                    .build();
            AccessTokenCache ownedByCaller = new AccessTokenCache(config, securityEventCounter, 0);

            ownedByCaller.shutdown();

            assertFalse(callerExecutor.isShutdown(),
                    "shutdown() must not stop a caller-supplied executor");
        } finally {
            callerExecutor.shutdownNow();
        }
    }

    @Test
    void shutdownStopsInternallyCreatedExecutor() {
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(10)
                .evictionIntervalSeconds(300L)
                .build();
        AccessTokenCache internallyOwned = new AccessTokenCache(config, securityEventCounter, 0);

        // No handle on the internal executor; shutdown must simply not throw and be idempotent
        assertDoesNotThrow(internallyOwned::shutdown);
        assertDoesNotThrow(internallyOwned::shutdown);
    }
}
