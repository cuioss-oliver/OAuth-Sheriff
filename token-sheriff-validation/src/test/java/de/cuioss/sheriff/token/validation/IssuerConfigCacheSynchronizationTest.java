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
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test to verify that IssuerConfigCache.resolveConfig() operates without
 * synchronization bottlenecks under high concurrency.
 *
 * This test directly measures the synchronization characteristics of
 * IssuerConfigCache to ensure lock-free operation and detect convoy effects.
 */
class IssuerConfigCacheSynchronizationTest {

    private IssuerConfigCache issuerConfigCache;
    private String issuerIdentifier;

    @BeforeEach
    void setUp() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        IssuerConfig issuerConfig = tokenHolder.getIssuerConfig();
        issuerIdentifier = issuerConfig.getIssuerIdentifier();

        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        issuerConfigCache = new IssuerConfigCache(List.of(issuerConfig), securityEventCounter);
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    @DisplayName("Measure performance during warmup phase")
    void measuresWarmupPhasePerformance() throws Exception {
        // Create multiple IssuerConfigCache instances to test warmup phase
        List<IssuerConfigCache> resolvers = new ArrayList<>();
        List<String> issuerIds = new ArrayList<>();
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        for (int i = 0; i < 5; i++) {
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            IssuerConfig config = tokenHolder.getIssuerConfig();
            resolvers.add(new IssuerConfigCache(List.of(config), securityEventCounter));
            issuerIds.add(config.getIssuerIdentifier());
        }

        int threadsPerResolver = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadsPerResolver * resolvers.size());
        CountDownLatch latch = new CountDownLatch(threadsPerResolver * resolvers.size());
        AtomicLong totalTime = new AtomicLong(0);
        AtomicInteger operations = new AtomicInteger(0);

        // Test each resolver with multiple threads simultaneously (warmup phase)
        for (int i = 0; i < resolvers.size(); i++) {
            IssuerConfigCache resolver = resolvers.get(i);
            String issuerId = issuerIds.get(i);
            for (int j = 0; j < threadsPerResolver; j++) {
                executor.submit(() -> {
                    try {
                        long startTime = System.nanoTime();

                        // First resolution hits any synchronization logic (warmup)
                        IssuerConfig result = resolver.resolveConfig(issuerId);

                        long duration = System.nanoTime() - startTime;
                        totalTime.addAndGet(duration);
                        operations.incrementAndGet();

                        assertNotNull(result);
                    } catch (IllegalArgumentException | IllegalStateException e) {
                        fail("Warmup test failed: " + e.getMessage());
                    } finally {
                        latch.countDown();
                    }
                });
            }
        }

        boolean completed = latch.await(10, TimeUnit.SECONDS);
        assertTrue(completed, "Warmup test did not complete within timeout");

        executor.shutdown();

        double avgTimeMs = totalTime.get() / (double) operations.get() / 1_000_000;


        // During warmup phase, IssuerConfigCache should be fast. Bound loosened to tolerate
        // parallel surefire forks / CI CPU oversubscription while still catching a blocking
        // regression; "all operations complete" below is the real correctness gate.
        assertTrue(avgTimeMs < 20, "Operations should be reasonable during warmup (was: %.2f ms)".formatted(avgTimeMs));
        assertEquals(operations.get(), threadsPerResolver * resolvers.size(), "All operations should complete");
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    @DisplayName("Measure post-warmup throughput for optimized cache")
    void measuresPostWarmupThroughput() throws Exception {
        // Pre-warm the resolver by doing a single resolution
        IssuerConfig warmupResult = issuerConfigCache.resolveConfig(issuerIdentifier);
        assertNotNull(warmupResult);

        // Now test performance after warmup
        int threadCount = 20;
        int operationsPerThread = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicLong totalTime = new AtomicLong(0);
        AtomicInteger totalOperations = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    long threadStartTime = System.nanoTime();

                    for (int j = 0; j < operationsPerThread; j++) {
                        IssuerConfig result = issuerConfigCache.resolveConfig(issuerIdentifier);
                        assertNotNull(result);
                        totalOperations.incrementAndGet();
                    }

                    long threadTime = System.nanoTime() - threadStartTime;
                    totalTime.addAndGet(threadTime);
                } catch (IllegalArgumentException | IllegalStateException e) {
                    fail("Post-warmup test failed: " + e.getMessage());
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean completed = latch.await(8, TimeUnit.SECONDS);
        assertTrue(completed, "Post-warmup test did not complete within timeout");

        executor.shutdown();

        double avgTimeMs = totalTime.get() / (double) totalOperations.get() / 1_000_000;
        double throughputOpsPerSec = totalOperations.get() / (totalTime.get() / 1_000_000_000.0);

        // After warmup, IssuerConfigCache should be fast. Bounds loosened to tolerate parallel
        // surefire forks / CI CPU oversubscription while still catching a blocking/locking
        // regression (orders of magnitude worse); "all operations complete" is the real gate.
        // Precise latency is tracked by the JMH benchmark-core module.
        assertTrue(avgTimeMs < 10, "Post-warmup operations should be reasonable (was: %.2f ms)".formatted(avgTimeMs));
        assertTrue(throughputOpsPerSec > 500, "Post-warmup throughput should be reasonable (was: %.0f ops/s)".formatted(throughputOpsPerSec));
        assertEquals(threadCount * operationsPerThread, totalOperations.get(), "All operations should complete");
    }
}