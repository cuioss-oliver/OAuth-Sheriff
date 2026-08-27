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
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Store / retrieve / atomic-remove and lifecycle-orchestration tests for
 * {@link InMemoryTokenStore}, {@link TokenLifecycleManager}, and {@link RefreshScheduler}
 * ({@code CLIENT-17} / {@code CLIENT-19}) — deliverable 9.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("TokenStore + lifecycle orchestration")
class TokenStoreTest {

    private static StoredToken bearerToken() {
        return new StoredToken(Generators.letterStrings(20, 40).next(), Generators.letterStrings(20, 40).next(),
                null, null, null);
    }

    @Test
    @DisplayName("Should store then retrieve a token bundle for a session")
    void shouldStoreAndRetrieve() {
        var store = new InMemoryTokenStore();
        String sessionId = Generators.letterStrings(10, 20).next();
        StoredToken token = bearerToken();

        store.store(sessionId, token);

        assertEquals(token, store.retrieve(sessionId).orElseThrow(), "the stored bundle is retrieved");
    }

    @Test
    @DisplayName("Should atomically remove and return the stored bundle, leaving nothing behind")
    void shouldRemoveAtomically() {
        var store = new InMemoryTokenStore();
        String sessionId = Generators.letterStrings(10, 20).next();
        StoredToken token = bearerToken();
        store.store(sessionId, token);

        var removed = store.remove(sessionId);

        assertAll("atomic remove",
                () -> assertEquals(token, removed.orElseThrow(), "remove returns the taken bundle"),
                () -> assertTrue(store.retrieve(sessionId).isEmpty(), "nothing remains after remove"),
                () -> assertTrue(store.remove(sessionId).isEmpty(), "a second remove returns empty"));
    }

    @Test
    @DisplayName("Should fail closed after logout — revokeAndClear leaves the session with no token")
    void shouldFailClosedAfterLogout() {
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        String sessionId = Generators.letterStrings(10, 20).next();
        StoredToken token = bearerToken();
        manager.store(sessionId, token);

        var cleared = manager.revokeAndClear(sessionId);

        assertAll("logout fail-closed",
                () -> assertEquals(token, cleared.orElseThrow(), "the cleared bundle is returned for AS revocation"),
                () -> assertTrue(manager.get(sessionId).isEmpty(),
                        "a stale token can no longer be read through the store after logout"),
                () -> assertTrue(manager.revokeAndClear(sessionId).isEmpty(),
                        "a repeated logout clears nothing"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "Cleared held tokens for session");
    }

    @Test
    @DisplayName("Should atomically update a present session and skip an absent one")
    void shouldUpdatePresentSessionOnly() {
        var store = new InMemoryTokenStore();
        String presentSession = Generators.letterStrings(10, 20).next();
        String absentSession = Generators.letterStrings(10, 20).next();
        StoredToken original = bearerToken();
        store.store(presentSession, original);
        String rotatedAccess = Generators.letterStrings(20, 40).next();

        var updated = store.update(presentSession, current -> current.refreshed(rotatedAccess, null, null, null));
        var skipped = store.update(absentSession, current -> current.refreshed(rotatedAccess, null, null, null));

        assertAll("atomic update",
                () -> assertEquals(rotatedAccess, updated.orElseThrow().accessToken(),
                        "a present session is transformed and returned"),
                () -> assertEquals(rotatedAccess, store.retrieve(presentSession).orElseThrow().accessToken(),
                        "the updated bundle replaces the stored one"),
                () -> assertTrue(skipped.isEmpty(), "an absent session yields empty"),
                () -> assertTrue(store.retrieve(absentSession).isEmpty(),
                        "an absent-session update never creates an entry"),
                () -> assertThrows(NullPointerException.class,
                        () -> store.update(presentSession, null), "a null updater is rejected"));
    }

    @Test
    @DisplayName("Should make applyRefresh a no-op once the session has been revoked (no stale write)")
    void shouldNotResurrectRevokedSessionOnRefresh() {
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        String sessionId = Generators.letterStrings(10, 20).next();
        manager.store(sessionId, bearerToken());
        manager.revokeAndClear(sessionId);

        var refreshed = manager.applyRefresh(sessionId, Generators.letterStrings(20, 40).next(), null, null, null);

        assertAll("refresh after logout is a no-op",
                () -> assertTrue(refreshed.isEmpty(),
                        "applying a refresh to a revoked session writes nothing back"),
                () -> assertTrue(manager.get(sessionId).isEmpty(),
                        "the revoked session stays empty — no token is resurrected"));
    }

    @Test
    @DisplayName("Should report proactive-refresh need based on the access-token expiry window")
    void shouldReportRefreshNeed() {
        var scheduler = new RefreshScheduler(Duration.ofSeconds(30));
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), scheduler);
        Instant now = Instant.now();
        String freshSession = Generators.letterStrings(10, 20).next();
        String expiringSession = Generators.letterStrings(10, 20).next();
        String unknownExpirySession = Generators.letterStrings(10, 20).next();
        manager.store(freshSession, new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null,
                now.plusSeconds(300)));
        manager.store(expiringSession, new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null,
                now.plusSeconds(10)));
        manager.store(unknownExpirySession, new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null,
                null));

        assertAll("refresh scheduling",
                () -> assertFalse(manager.needsRefresh(freshSession, now), "a token far from expiry is not refreshed"),
                () -> assertTrue(manager.needsRefresh(expiringSession, now),
                        "a token inside the refresh window is refreshed"),
                () -> assertTrue(manager.needsRefresh(unknownExpirySession, now),
                        "a token with unknown (null) expiry is treated as refresh-eligible"),
                () -> assertFalse(manager.needsRefresh(Generators.letterStrings(10, 20).next(), now),
                        "an absent session never needs refresh"));
    }

    @Test
    @DisplayName("Should reject a null token, blank session id, and negative refresh lead")
    void shouldRejectInvalidInputs() {
        var store = new InMemoryTokenStore();
        var sessionId = Generators.letterStrings(10, 20).next();
        var token = bearerToken();
        var negativeLead = Duration.ofSeconds(-1);

        assertAll("input guards",
                () -> assertThrows(NullPointerException.class,
                        () -> store.store(sessionId, null)),
                () -> assertThrows(IllegalArgumentException.class, () -> store.store("  ", token)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> new RefreshScheduler(negativeLead)));
    }

    @Test
    @DisplayName("Should treat the exact refresh-window edge as eligible and one instant earlier as not (injected clock)")
    void shouldRefreshExactlyAtWindowEdge() {
        var refreshLead = Duration.ofSeconds(30);
        var scheduler = new RefreshScheduler(refreshLead);
        // Injected clock: every reference instant is derived from a fixed base, so the boundary is
        // exercised deterministically without any wall-clock sleep.
        Instant expiresAt = Instant.now().plusSeconds(300);
        Instant windowOpensAt = expiresAt.minus(refreshLead);
        StoredToken token = new StoredToken(Generators.letterStrings(20, 40).next(), null, null, null, expiresAt);

        assertAll("refresh-window edge (injected clock)",
                () -> assertFalse(scheduler.needsRefresh(token, windowOpensAt.minusNanos(1)),
                        "one instant before the window opens is not yet refresh-eligible"),
                () -> assertTrue(scheduler.needsRefresh(token, windowOpensAt),
                        "exactly at the window edge the token is refresh-eligible"),
                () -> assertTrue(scheduler.needsRefresh(token, windowOpensAt.plusNanos(1)),
                        "just inside the window the token is refresh-eligible"),
                () -> assertTrue(scheduler.needsRefresh(token, expiresAt),
                        "at expiry the token is refresh-eligible"));
    }

    @Test
    @DisplayName("Should keep logout fail-closed under a concurrent refresh — a revoked session is never resurrected")
    void shouldNotResurrectSessionUnderConcurrentRefreshAndLogout() {
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        // computeIfPresent makes retrieve-transform-store atomic, so whichever thread runs first, the
        // final state after a concurrent logout is always empty: a refresh can never resurrect a
        // revoked session. A CyclicBarrier releases both threads simultaneously each iteration, so the
        // interleaving is genuinely exercised without any timing assumption (no flake).
        int iterations = 500;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int i = 0; i < iterations; i++) {
                String sessionId = Generators.letterStrings(10, 20).next();
                manager.store(sessionId, bearerToken());
                String rotatedAccess = Generators.letterStrings(20, 40).next();
                var barrier = new CyclicBarrier(2);

                Callable<Void> refreshTask = () -> {
                    barrier.await();
                    manager.applyRefresh(sessionId, rotatedAccess, null, null, null);
                    return null;
                };
                Callable<Void> logoutTask = () -> {
                    barrier.await();
                    manager.revokeAndClear(sessionId);
                    return null;
                };
                var refreshResult = pool.submit(refreshTask);
                var logoutResult = pool.submit(logoutTask);

                assertDoesNotThrow(() -> {
                    refreshResult.get();
                    logoutResult.get();
                }, "neither concurrent operation fails");
                assertTrue(manager.get(sessionId).isEmpty(),
                        "after a concurrent logout the session holds no token — refresh cannot resurrect it");
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
