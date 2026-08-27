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
package de.cuioss.sheriff.token.client.lifecycle;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-session isolation tests for {@link InMemoryTokenStore} ({@code CLIENT-22}) — deliverable 9.
 * <p>
 * Verifies that tokens stored for one session never leak into another, including under concurrent
 * store/retrieve/remove across many sessions.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("TokenStore cross-session isolation")
class StorageIsolationTest {

    @Test
    @DisplayName("Should keep each session's token isolated from every other session")
    void shouldIsolateSessions() {
        var store = new InMemoryTokenStore();
        String sessionA = Generators.letterStrings(10, 20).next();
        String sessionB = Generators.letterStrings(21, 30).next();
        StoredToken tokenA = new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, null);
        StoredToken tokenB = new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, null);

        store.store(sessionA, tokenA);
        store.store(sessionB, tokenB);
        store.remove(sessionA);

        assertAll("isolation",
                () -> assertTrue(store.retrieve(sessionA).isEmpty(), "removing A does not affect A's own emptiness"),
                () -> assertEquals(tokenB, store.retrieve(sessionB).orElseThrow(),
                        "removing A leaves B untouched"));
    }

    @Test
    @DisplayName("Should keep every session's token intact under concurrent multi-session access")
    void shouldRemainConsistentUnderConcurrency() throws Exception {
        var store = new InMemoryTokenStore();
        int sessions = 64;
        List<String> sessionIds = new ArrayList<>();
        var expected = new ConcurrentHashMap<String, StoredToken>();
        for (int i = 0; i < sessions; i++) {
            String sessionId = "session-" + i + "-" + Generators.letterStrings(5, 10).next();
            sessionIds.add(sessionId);
            expected.put(sessionId, new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, null));
        }

        ExecutorService pool = Executors.newFixedThreadPool(16);
        var start = new CountDownLatch(1);
        for (String sessionId : sessionIds) {
            pool.submit(() -> {
                awaitQuietly(start);
                store.store(sessionId, expected.get(sessionId));
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "all stores complete");

        assertAll("every session intact",
                sessionIds.stream().map(id -> () ->
                        assertEquals(expected.get(id), store.retrieve(id).orElseThrow(),
                                "session " + id + " retains its own token")));
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
