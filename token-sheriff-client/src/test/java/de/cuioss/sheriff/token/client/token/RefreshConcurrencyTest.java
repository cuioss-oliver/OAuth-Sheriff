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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrency contract for {@link RefreshTokenFamily} ({@code CLIENT-17} / {@code CLIENT-22}) —
 * deliverable 4.
 * <p>
 * When many threads race to redeem the same current refresh token, the family must serialize the
 * rotation so that <em>exactly one</em> thread wins and every loser is treated as a reuse of the
 * now-superseded token, revoking the family. This rules out a race where two callers both believe
 * they hold a valid rotation.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("RefreshTokenFamily concurrent-rotation safety")
class RefreshConcurrencyTest {

    private static final int THREADS = 16;

    @Test
    @DisplayName("Should let exactly one concurrent rotation win and revoke the family for the rest")
    void shouldSerializeConcurrentRotations() throws Exception {
        String initial = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        var successes = new AtomicInteger();
        var reuseRejections = new AtomicInteger();

        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(THREADS);
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        try {
            for (int i = 0; i < THREADS; i++) {
                String candidate = Generators.letterStrings(20, 40).next();
                pool.execute(() -> {
                    try {
                        startGate.await();
                        family.rotate(initial, candidate);
                        successes.incrementAndGet();
                    } catch (ClientProtocolException reuse) {
                        reuseRejections.incrementAndGet();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneGate.countDown();
                    }
                });
            }
            startGate.countDown();
            assertTrue(doneGate.await(10, TimeUnit.SECONDS), "all rotation attempts must complete");
        } finally {
            pool.shutdownNow();
        }

        assertAll("concurrent rotation outcome",
                () -> assertEquals(1, successes.get(), "exactly one concurrent rotation may win"),
                () -> assertEquals(THREADS - 1, reuseRejections.get(),
                        "every losing rotation must be rejected as reuse"),
                () -> assertTrue(family.isRevoked(), "a lost race must revoke the family"));
    }
}
