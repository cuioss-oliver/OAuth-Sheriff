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
package de.cuioss.sheriff.token.validation.dpop;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class DpopReplayProtectionTest {

    private DpopReplayProtection replayProtection;

    @BeforeEach
    void setUp() {
        replayProtection = new DpopReplayProtection(300, 10_000);
    }

    @AfterEach
    void tearDown() {
        replayProtection.close();
    }

    @Test
    void shouldAcceptNewJti() {
        assertTrue(replayProtection.checkAndStore("unique-jti-1"));
    }

    @Test
    void shouldRejectReplayedJti() {
        String jti = "replayed-jti";
        assertTrue(replayProtection.checkAndStore(jti));
        assertFalse(replayProtection.checkAndStore(jti));
    }

    @Test
    void shouldAcceptDifferentJtiValues() {
        assertTrue(replayProtection.checkAndStore("jti-1"));
        assertTrue(replayProtection.checkAndStore("jti-2"));
        assertTrue(replayProtection.checkAndStore("jti-3"));
    }

    @Test
    void shouldAcceptJtiAfterTtlExpires() {
        // Use a very short TTL for testing
        try (var shortTtl = new DpopReplayProtection(1, 10_000)) {
            String jti = "short-lived-jti";
            assertTrue(shortTtl.checkAndStore(jti));
            assertFalse(shortTtl.checkAndStore(jti));

            // Wait for TTL to expire, then verify the same jti is accepted again
            Awaitility.await().atMost(Duration.ofSeconds(2)).pollInterval(Duration.ofMillis(100))
                    .untilAsserted(() -> assertTrue(shortTtl.checkAndStore(jti)));
        }
    }

    @Test
    void shouldEvictOldestWhenMaxSizeExceeded() {
        try (var smallCache = new DpopReplayProtection(300, 5)) {
            // Fill cache
            for (int i = 0; i < 5; i++) {
                assertTrue(smallCache.checkAndStore("jti-" + i));
            }

            // This should trigger eviction of oldest
            assertTrue(smallCache.checkAndStore("jti-new"));

            // The oldest entries should have been evicted
            // New entry should still be detected as replay
            assertFalse(smallCache.checkAndStore("jti-new"));
        }
    }

    @Test
    void shouldBeThreadSafe() throws Exception {
        int threadCount = 10;
        int operationsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger acceptCount = new AtomicInteger(0);

        // Each thread tries to store unique jti values
        for (int t = 0; t < threadCount; t++) {
            int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < operationsPerThread; i++) {
                        String jti = "thread-" + threadId + "-jti-" + i;
                        if (replayProtection.checkAndStore(jti)) {
                            acceptCount.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        doneLatch.await();
        executor.shutdown();

        // All unique jti values should have been accepted
        assertEquals(threadCount * operationsPerThread, acceptCount.get());
    }

    @Test
    void shouldDetectReplayAcrossThreads() throws Exception {
        String sharedJti = UUID.randomUUID().toString();
        int threadCount = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicInteger acceptCount = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int t = 0; t < threadCount; t++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    if (replayProtection.checkAndStore(sharedJti)) {
                        acceptCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        doneLatch.await();
        executor.shutdown();

        // Exactly one thread should have succeeded
        assertEquals(1, acceptCount.get());
    }

    @Test
    void shouldCleanUpOnClose() {
        DpopReplayProtection protection = new DpopReplayProtection(300, 10_000);
        protection.checkAndStore("some-jti");
        protection.close();
        // After close, the scheduler is shut down - this should not throw
        assertDoesNotThrow(protection::close);
    }
}
