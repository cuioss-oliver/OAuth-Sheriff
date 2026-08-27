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
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit test for IssuerConfigCache to verify:
 * - Lazy initialization and caching behavior
 * - Thread safety and concurrency handling
 * - Cache optimization from ConcurrentHashMap to immutable map
 * - Health checking and pending queue management
 * - Error handling for missing/unhealthy issuers
 */
@EnableTestLogger
class IssuerConfigCacheTest {

    private SecurityEventCounter securityEventCounter;
    private TestTokenHolder tokenHolder1;
    private TestTokenHolder tokenHolder2;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();

        // Create multiple test token holders for testing
        tokenHolder1 = TestTokenGenerators.accessTokens().next();
        tokenHolder2 = TestTokenGenerators.accessTokens().next();
    }

    @Nested
    @DisplayName("Lazy Initialization Tests")
    class LazyInitializationTests {

        @Test
        @DisplayName("Resolve issuer configuration from pending queue")
        void resolvesIssuerFromPendingQueue() {
            IssuerConfig config = tokenHolder1.getIssuerConfig();
            String issuerIdentifier = config.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            IssuerConfig result = resolver.resolveConfig(issuerIdentifier);

            assertSame(config, result);
        }

        @Test
        @DisplayName("Cache issuer configuration after first resolution")
        void cachesIssuerAfterFirstResolution() {
            IssuerConfig config = tokenHolder1.getIssuerConfig();
            String issuerIdentifier = config.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            // First call
            IssuerConfig result1 = resolver.resolveConfig(issuerIdentifier);

            // Second call - should hit cache
            IssuerConfig result2 = resolver.resolveConfig(issuerIdentifier);

            assertSame(result1, result2);
            assertSame(config, result1);
        }

        @Test
        @DisplayName("Process multiple issuers lazily")
        void processesMultipleIssuersLazily() {
            IssuerConfig config1 = tokenHolder1.getIssuerConfig();
            IssuerConfig config2 = tokenHolder2.getIssuerConfig();
            String issuer1 = config1.getIssuerIdentifier();
            String issuer2 = config2.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config1, config2),
                    securityEventCounter
            );

            // Resolve first issuer
            IssuerConfig result1 = resolver.resolveConfig(issuer1);
            assertEquals(config1.getIssuerIdentifier(), result1.getIssuerIdentifier());

            // Resolve second issuer
            IssuerConfig result2 = resolver.resolveConfig(issuer2);
            assertEquals(config2.getIssuerIdentifier(), result2.getIssuerIdentifier());

            // Both should now be cached (same instances on repeated calls)
            assertSame(result1, resolver.resolveConfig(issuer1));
            assertSame(result2, resolver.resolveConfig(issuer2));
        }
    }

    @Nested
    @DisplayName("Empty Configuration Tests")
    class EmptyConfigurationTests {

        @Test
        @DisplayName("Handle resolver with no enabled configs")
        void handlesResolverWithNoEnabledConfigs() {
            // Create resolver with all disabled configs
            IssuerConfig disabledConfig = IssuerConfig.builder()
                    .enabled(false)
                    .issuerIdentifier("https://disabled-issuer.com")
                    .build();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(disabledConfig),
                    securityEventCounter
            );

            // Try to resolve any issuer - should throw exception
            TokenValidationException exception = assertThrows(
                    TokenValidationException.class,
                    () -> resolver.resolveConfig("https://disabled-issuer.com")
            );

            assertTrue(exception.getMessage().contains("disabled-issuer.com"));
            assertEquals(SecurityEventCounter.EventType.NO_ISSUER_CONFIG, exception.getEventType());
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Throw exception for unknown issuer")
        void throwsExceptionForUnknownIssuer() {
            IssuerConfig config = tokenHolder1.getIssuerConfig();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            TokenValidationException exception = assertThrows(
                    TokenValidationException.class,
                    () -> resolver.resolveConfig("https://unknown-issuer.com")
            );

            assertTrue(exception.getMessage().contains("unknown-issuer.com"));
            assertEquals(SecurityEventCounter.EventType.NO_ISSUER_CONFIG, exception.getEventType());

            // Verify log message
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.NO_ISSUER_CONFIG.resolveIdentifierString());
        }

        @Test
        @DisplayName("Increment security event counter for missing issuer")
        void incrementsSecurityEventCounterForMissingIssuer() {
            IssuerConfig config = tokenHolder1.getIssuerConfig();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG);

            assertThrows(TokenValidationException.class, () ->
                    resolver.resolveConfig("https://unknown-issuer.com"));

            assertEquals(initialCount + 1,
                    securityEventCounter.getCount(SecurityEventCounter.EventType.NO_ISSUER_CONFIG));
        }

        @Test
        @DisplayName("Should log info for skipped disabled issuer")
        void shouldLogInfoForSkippedDisabledIssuer() {
            IssuerConfig enabledConfig = tokenHolder1.getIssuerConfig();
            IssuerConfig disabledConfig = IssuerConfig.builder()
                    .enabled(false)
                    .build();

            new IssuerConfigCache(
                    List.of(enabledConfig, disabledConfig),
                    securityEventCounter
            );

            // The log message is triggered during constructor when processing configs
            // Verify ISSUER_CONFIG_SKIPPED was logged for disabled issuer
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO,
                    JWTValidationLogMessages.INFO.ISSUER_CONFIG_SKIPPED.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should log warning for unhealthy issuer config")
        void shouldLogWarningForUnhealthyIssuer() {
            // Create a config that will be considered unhealthy
            // An issuer is unhealthy when its JwksLoader status is not OK
            IssuerConfig config = IssuerConfig.builder()
                    .issuerIdentifier("https://test-unhealthy-issuer.com")
                    .jwksContent("invalid-jwks-content") // This will cause loader to be unhealthy
                    .audienceValidationDisabled(true)
                    .build();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            // Try to resolve - this should trigger the unhealthy issuer warning
            try {
                resolver.resolveConfig("https://test-unhealthy-issuer.com");
            } catch (TokenValidationException ignored) {
                // Expected - unhealthy issuer may cause validation exception
            }

            // Verify ISSUER_CONFIG_LOAD_FAILED was logged for unhealthy issuer
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.ISSUER_CONFIG_LOAD_FAILED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Handle concurrent access during lazy initialization")
        void handlesConcurrentAccessDuringLazyInitialization() throws Exception {
            IssuerConfig config = tokenHolder1.getIssuerConfig();
            String issuerIdentifier = config.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            int threadCount = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            List<IssuerConfig> results = new CopyOnWriteArrayList<>();
            AtomicInteger exceptionCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        IssuerConfig result = resolver.resolveConfig(issuerIdentifier);
                        results.add(result);
                    } catch (IllegalArgumentException | IllegalStateException e) {
                        exceptionCount.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(5, TimeUnit.SECONDS));
            executor.shutdown();

            assertEquals(0, exceptionCount.get(), "No exceptions should occur during concurrent access");
            assertEquals(threadCount, results.size());
            results.forEach(result -> assertSame(config, result));
        }

        @Test
        @DisplayName("Maintain consistency during concurrent cache optimization")
        void maintainsConsistencyDuringConcurrentOptimization() throws Exception {
            // Create multiple configs
            List<IssuerConfig> configs = new ArrayList<>();
            List<String> issuerIds = new ArrayList<>();

            for (int i = 0; i < 3; i++) {
                TestTokenHolder holder = TestTokenGenerators.accessTokens().next();
                IssuerConfig config = holder.getIssuerConfig();
                configs.add(config);
                issuerIds.add(config.getIssuerIdentifier());
            }

            IssuerConfigCache resolver = new IssuerConfigCache(
                    configs,
                    securityEventCounter
            );

            int threadCount = 15;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger exceptionCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final String targetIssuer = issuerIds.get(i % issuerIds.size());
                executor.submit(() -> {
                    try {
                        IssuerConfig result = resolver.resolveConfig(targetIssuer);
                        assertNotNull(result);
                        assertEquals(targetIssuer, result.getIssuerIdentifier());
                        successCount.incrementAndGet();
                    } catch (IllegalArgumentException | IllegalStateException e) {
                        exceptionCount.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            executor.shutdown();

            assertEquals(0, exceptionCount.get(), "No exceptions should occur during concurrent access");
            assertEquals(threadCount, successCount.get(), "All operations should succeed");
        }
    }

    @Nested
    @DisplayName("Double-Checked Locking Tests")
    class DoubleCheckedLockingTests {

        @Test
        @DisplayName("Use fast path for cached configurations")
        void usesFastPathForCachedConfigs() {
            IssuerConfig config = tokenHolder1.getIssuerConfig();
            String issuerIdentifier = config.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            // First call - should go through slow path
            IssuerConfig result1 = resolver.resolveConfig(issuerIdentifier);

            // Second call - should use fast path
            IssuerConfig result2 = resolver.resolveConfig(issuerIdentifier);

            assertSame(result1, result2);
            assertSame(config, result1);
        }

        @Test
        @DisplayName("Handle double-checked locking correctly under high concurrency")
        void handlesDoubleCheckedLockingCorrectly() throws Exception {
            IssuerConfig config = tokenHolder1.getIssuerConfig();
            String issuerIdentifier = config.getIssuerIdentifier();

            IssuerConfigCache resolver = new IssuerConfigCache(
                    List.of(config),
                    securityEventCounter
            );

            int threadCount = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CyclicBarrier barrier = new CyclicBarrier(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        // Synchronize all threads to start at exactly the same time
                        barrier.await();

                        IssuerConfig result = resolver.resolveConfig(issuerIdentifier);
                        assertSame(config, result);
                        successCount.incrementAndGet();

                    } catch (IllegalArgumentException | IllegalStateException | BrokenBarrierException ignored) {
                        // Noop, not tested here
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(5, TimeUnit.SECONDS));
            executor.shutdown();

            assertEquals(threadCount, successCount.get(), "All threads should succeed with double-checked locking");
        }
    }

}