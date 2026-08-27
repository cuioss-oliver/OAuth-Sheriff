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

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for concurrent access to TokenValidator to reproduce the
 * UnsupportedOperationException race condition.
 */
class TokenValidatorConcurrencyTest {

    private static final int THREAD_COUNT = 200;
    private static final int ITERATIONS_PER_THREAD = 10;

    /**
     * Reproduces the race condition where multiple threads try to resolve issuer configs
     * while optimization to read-only access happens concurrently.
     *
     * This test should reproduce the UnsupportedOperationException that occurs when:
     * 1. Thread A optimizes the map to read-only (Map.copyOf)
     * 2. Thread B tries to put() into the now-immutable map
     */
    @RepeatedTest(5)
    void shouldReproduceRaceConditionWithReadOnlyOptimization() throws Exception {
        // Generate test tokens using existing infrastructure
        var testToken1 = TestTokenGenerators.accessTokens().next();
        var testToken2 = TestTokenGenerators.accessTokens().next();

        // Create multiple issuer configs to trigger the race condition
        var issuerConfig1 = testToken1.getIssuerConfig();
        var issuerConfig2 = testToken2.getIssuerConfig();

        var parserConfig = ParserConfig.builder().build();
        var tokenValidator = TokenValidator.builder().parserConfig(parserConfig).issuerConfig(issuerConfig1).issuerConfig(issuerConfig2).build();

        // Use the first test token for validation
        var validJwt = testToken1.getRawToken();

        // Atomic counter for tracking results
        AtomicInteger successCount = new AtomicInteger(0);

        // Create thread pool and coordination
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch completionLatch = new CountDownLatch(THREAD_COUNT);

        // Submit concurrent tasks
        for (int i = 0; i < THREAD_COUNT; i++) {
            executor.submit(() -> {
                try {
                    // Wait for all threads to be ready
                    startLatch.await();

                    // Perform multiple iterations to increase chance of race condition
                    var request = AccessTokenRequest.of(validJwt);
                    for (int j = 0; j < ITERATIONS_PER_THREAD; j++) {
                        // This should trigger the resolveIssuerConfig method
                        tokenValidator.createAccessToken(request);
                        successCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completionLatch.countDown();
                }
            });
        }

        // Start all threads simultaneously to maximize chance of race condition
        startLatch.countDown();

        // Wait for completion with timeout
        assertTrue(completionLatch.await(30, TimeUnit.SECONDS),
                "Test should complete within 30 seconds");

        executor.shutdown();

        // Verify all operations succeeded - any exception will cause test to fail naturally
        assertEquals(THREAD_COUNT * ITERATIONS_PER_THREAD, successCount.get(),
                "All token validation operations should succeed");
    }

    /**
     * Simplified test that focuses specifically on the map optimization race condition.
     */
    @Test
    void shouldDemonstrateMapOptimizationRaceCondition() throws Exception {
        // Generate test token using existing infrastructure
        var testToken = TestTokenGenerators.accessTokens().next();
        var issuerConfig = testToken.getIssuerConfig();
        var tokenValidator = TokenValidator.builder().parserConfig(ParserConfig.builder().build()).issuerConfig(issuerConfig).build();
        var validJwt = testToken.getRawToken();

        int threadCount = 50;
        int iterationsPerThread = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicReference<Throwable> firstFailure = new AtomicReference<>();

        // Launch multiple threads to create access tokens simultaneously
        for (int i = 0; i < threadCount; i++) {
            var request = AccessTokenRequest.of(validJwt);
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterationsPerThread; j++) {
                        tokenValidator.createAccessToken(request);
                        successCount.incrementAndGet();
                    }
                } catch (RuntimeException e) {
                    // A submitted Runnable would otherwise swallow the exception into the (unread)
                    // Future — capture it so the map-optimization race actually fails the test.
                    firstFailure.compareAndSet(null, e);
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(20, TimeUnit.SECONDS), "All threads should complete within the timeout");
        executor.shutdown();

        assertNull(firstFailure.get(),
                () -> "No thread may observe a map-optimization race exception, but one did: " + firstFailure.get());
        assertEquals(threadCount * iterationsPerThread, successCount.get(),
                "Every concurrent createAccessToken call must succeed");
    }
}
