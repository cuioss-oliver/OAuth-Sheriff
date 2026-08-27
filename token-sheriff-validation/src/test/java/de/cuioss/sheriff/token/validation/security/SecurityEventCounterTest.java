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
package de.cuioss.sheriff.token.validation.security;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link SecurityEventCounter}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.3">VALIDATION-7.3: Security Events</a> (security event monitoring and tracking)</li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-10.1">VALIDATION-10.1: Thread Safety</a></li>
 * </ul>
 * <p>
 * This test class ensures that security events are properly counted, can be reset,
 * and that the counter implementation is thread-safe for concurrent access.
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc#security-controls">Security Controls Specification</a>
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests SecurityEventCounter functionality")
class SecurityEventCounterTest {

    @Test
    @DisplayName("Should increment counter")
    void shouldIncrementCounter() {
        var counter = new SecurityEventCounter();
        var count = counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        assertEquals(1, count, "Increment should return 1");
        assertEquals(1, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY), "Counter should be 1 after increment");
    }

    @Test
    @DisplayName("Should return zero for non-existing counter")
    void shouldReturnZeroForNonExistingCounter() {
        var counter = new SecurityEventCounter();
        var count = counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY);
        assertEquals(0, count, "Non-existing counter should return 0");
    }

    @Test
    @DisplayName("Should reset all counters")
    void shouldResetAllCounters() {
        var counter = new SecurityEventCounter();
        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        counter.reset();
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY), "TOKEN_EMPTY counter should be reset to 0");
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM), "MISSING_CLAIM counter should be reset to 0");
    }

    @Test
    @DisplayName("Should get all counters")
    void shouldGetAllCounters() {
        var counter = new SecurityEventCounter();
        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        counter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        var counters = counter.getCounters();
        assertEquals(2, counters.size(), "Should have 2 counter types");
        assertEquals(1L, counters.get(SecurityEventCounter.EventType.TOKEN_EMPTY), "TOKEN_EMPTY should be 1");
        assertEquals(2L, counters.get(SecurityEventCounter.EventType.MISSING_CLAIM), "MISSING_CLAIM should be 2");
    }

    @Test
    @DisplayName("Should be thread safe")
    void shouldBeThreadSafe() {
        var threadCount = 10;
        var incrementsPerThread = 1000;
        var expectedTotal = threadCount * incrementsPerThread;
        var counter = new SecurityEventCounter();
        var startLatch = new CountDownLatch(1);
        var completedThreads = new AtomicInteger(0);
        var executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < incrementsPerThread; j++) {
                        counter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completedThreads.incrementAndGet();
                }
            });
        }

        startLatch.countDown();

        await("All threads to complete their increment operations")
                .atMost(10, SECONDS)
                .until(() -> completedThreads.get() == threadCount);

        executor.shutdown();

        await("Counter to reach expected total from all threads")
                .atMost(1, SECONDS)
                .until(() -> counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY) == expectedTotal);

        assertEquals(expectedTotal, counter.getCount(SecurityEventCounter.EventType.TOKEN_EMPTY),
                "Counter should equal total increments from all threads");
    }
}