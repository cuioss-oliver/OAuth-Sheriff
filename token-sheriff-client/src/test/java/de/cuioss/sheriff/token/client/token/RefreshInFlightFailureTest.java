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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.lifecycle.TokenStore;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lifecycle state preservation when a wired refresh <em>fails</em> mid-rotation.
 * <p>
 * {@code RefreshErrorPathSpecIT} pins the {@link RefreshFlow}-level typed refusal; the uncovered half
 * is what {@link TokenLifecycleManager} does around it. A transport failure must leave the rotation
 * family unadvanced, the store untouched, and the single-flight entry released, so the very next
 * refresh with the same still-valid token succeeds instead of being misclassified as reuse. A
 * concurrent caller that joined the failed rotation must observe the same failure rather than
 * redeeming the token a second time.
 * <p>
 * The cases live here rather than in {@code RefreshAdversarialTest} so neither class exceeds the
 * module's 400-line budget; both consume the shared {@link RefreshTestSupport} fixture.
 * <p>
 * <strong>Coverage note.</strong> {@code awaitInFlight} carries two rethrow branches — the
 * {@code RuntimeException} cause rethrown directly, and a {@code CompletionException} rethrown when
 * the cause is not a {@code RuntimeException}. Only the first is exercised here, because the second is
 * unreachable through the public API: the in-flight future is completed exceptionally from a
 * {@code catch (RuntimeException)} block alone, so its cause is a {@code RuntimeException} by
 * construction. The second branch is defensive residue, not a behaviour a test can pin.
 *
 * @since 1.0
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Wired refresh: lifecycle state preservation on a failed rotation")
class RefreshInFlightFailureTest extends RefreshTestSupport {

    private static final long AWAIT_SECONDS = 10;

    @BeforeEach
    void setUp() {
        initRefreshFixture();
    }

    @Test
    @DisplayName("Should leave the stored bundle untouched when the token endpoint fails mid-refresh")
    void shouldPreserveStoredBundleOnTransportFailure(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String originalIdToken = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, originalIdToken));
        getModuleDispatcher().returnOAuthError();
        var clientAuth = clientAuth(config);

        assertThrows(TransportException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        StoredToken held = manager.get(session).orElseThrow();
        assertAll("failed rotation leaves the session exactly as it was",
                () -> assertEquals(rt1, held.refreshToken(),
                        "the still-valid refresh token must survive a failed rotation"),
                () -> assertEquals(originalIdToken, held.idToken(),
                        "the stored ID token must survive a failed rotation"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "a transport failure is not reuse and must not revoke the family"));
    }

    @Test
    @DisplayName("Should not misclassify a retry with the same still-valid token as refresh-token reuse")
    void shouldNotMisclassifyRetryAfterFailureAsReuse(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String rt2 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));
        getModuleDispatcher().returnOAuthError();
        var clientAuth = clientAuth(config);
        assertThrows(TransportException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        getModuleDispatcher().reset();
        getModuleDispatcher().respondWith(
                TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        StoredToken refreshed = manager
                .refresh(session, metadata, flow, revocationClient, idBridge, clientAuth)
                .orElseThrow();

        assertAll("the family was never advanced by the failed attempt",
                () -> assertEquals(rt2, refreshed.refreshToken(),
                        "the retry with the same token must rotate normally, not fail as reuse"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "the retry must not be classified as reuse and must not revoke the family"));
    }

    @Test
    @DisplayName("Should surface the same failure to a caller that joined the failed in-flight rotation")
    void shouldPropagateFailureToConcurrentJoiner(URIBuilder uriBuilder) throws Exception {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        ClientAuthentication clientAuth = clientAuth(config);
        var rendezvous = new SingleFlightRendezvousStore(new InMemoryTokenStore());
        CountDownLatch joined = new CountDownLatch(1);
        TokenLifecycleManager manager = new TokenLifecycleManager(rendezvous, new RefreshScheduler()) {
            @Override
            protected void onSingleFlightJoin(String sessionId) {
                joined.countDown();
            }
        };
        String session = Generators.letterStrings(10, 20).next();
        manager.store(session, bearerBundle(Generators.letterStrings(20, 40).next(), null));
        getModuleDispatcher().returnOAuthError();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Class<?>> leader = pool.submit(() -> thrownBy(
                    () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth)));
            assertTrue(rendezvous.awaitRegistration(AWAIT_SECONDS, TimeUnit.SECONDS),
                    "the leading caller must register its single-flight entry");
            Future<Class<?>> joiner = pool.submit(() -> thrownBy(
                    () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth)));
            // The join point itself, not a proxy for it: the hook fires only once the joining caller's
            // putIfAbsent has returned the leading caller's future, so from here on the joining caller
            // is holding that future and cannot start a redemption of its own — whatever the scheduler
            // does with the two threads after the release below.
            assertTrue(joined.await(AWAIT_SECONDS, TimeUnit.SECONDS),
                    "the joining caller must reach the single-flight join point");
            rendezvous.releaseLeader();

            assertAll("both callers observe the one failure",
                    () -> assertEquals(TransportException.class, leader.get(AWAIT_SECONDS, TimeUnit.SECONDS),
                            "the leading caller surfaces the transport failure"),
                    () -> assertEquals(TransportException.class, joiner.get(AWAIT_SECONDS, TimeUnit.SECONDS),
                            "the joining caller is rethrown the leader's failure, unwrapped from CompletionException"),
                    () -> assertEquals(1, getModuleDispatcher().getCallCounter(),
                            "the joining caller must join the in-flight rotation, never redeem the token itself"));
        } finally {
            rendezvous.releaseLeader();
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("Should release the in-flight entry after a failed rotation so the session stays refreshable")
    void shouldReleaseInFlightEntryAfterFailure(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt2 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(Generators.letterStrings(20, 40).next(), null));
        getModuleDispatcher().returnOAuthError();
        var clientAuth = clientAuth(config);
        assertThrows(TransportException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        getModuleDispatcher().reset();
        getModuleDispatcher().respondWith(
                TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        Optional<StoredToken> refreshed = manager.refresh(session, metadata, flow, revocationClient, idBridge,
                clientAuth);

        assertAll("the failed rotation left no stale single-flight entry",
                () -> assertTrue(refreshed.isPresent(),
                        "a later refresh must not join a completed, failed rotation"),
                () -> assertEquals(rt2, refreshed.orElseThrow().refreshToken(),
                        "the later refresh redeems for itself and rotates"),
                () -> assertEquals(1, getModuleDispatcher().getCallCounter(),
                        "the later refresh reaches the token endpoint rather than replaying the failed result"));
    }

    /** Runs {@code action} and reports the type of the throwable it raised. */
    private static Class<?> thrownBy(Runnable action) {
        return assertThrows(Throwable.class, action::run).getClass();
    }

    /**
     * A {@link TokenStore} decorator that turns "the leading caller has registered its single-flight
     * entry" into a latch the production path itself trips, so the concurrent case needs no timing
     * assumption at all.
     * <p>
     * {@code TokenLifecycleManager.refresh} registers its in-flight entry <em>before</em> it delegates
     * to the store, so the first {@link #retrieve(String)} is reached strictly after that registration.
     * Announcing it there and parking the caller keeps the registration observably open until
     * {@link #releaseLeader()}, which is what guarantees the joining caller finds a rotation to join
     * rather than starting one of its own.
     * <p>
     * This decorator only opens the window; it deliberately does not try to observe the joining caller
     * arriving in it. Both earlier attempts did exactly that and stayed flaky, because every signal a
     * decorated collaborator can offer — the dispatcher's call counter, this store's {@code retrieve} —
     * fires strictly <em>before</em> the join and is therefore a prediction, not a fact. The join itself
     * is announced by {@code TokenLifecycleManager.onSingleFlightJoin}, overridden in the test above;
     * releasing the leader only after that hook has fired is what makes the case deterministic.
     */
    private static final class SingleFlightRendezvousStore implements TokenStore {

        private final TokenStore delegate;
        private final CountDownLatch registered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicBoolean leaderArrived = new AtomicBoolean();

        SingleFlightRendezvousStore(TokenStore delegate) {
            this.delegate = delegate;
        }

        /** Waits for the leading caller to have registered its single-flight entry. */
        boolean awaitRegistration(long timeout, TimeUnit unit) throws InterruptedException {
            return registered.await(timeout, unit);
        }

        /** Lets the parked leading caller proceed; idempotent, so the finally block may repeat it. */
        void releaseLeader() {
            release.countDown();
        }

        @Override
        public Optional<StoredToken> retrieve(String sessionId) {
            if (leaderArrived.compareAndSet(false, true)) {
                registered.countDown();
                awaitRelease();
            }
            return delegate.retrieve(sessionId);
        }

        @Override
        public void store(String sessionId, StoredToken token) {
            delegate.store(sessionId, token);
        }

        @Override
        public Optional<StoredToken> remove(String sessionId) {
            return delegate.remove(sessionId);
        }

        @Override
        public Optional<StoredToken> update(String sessionId, UnaryOperator<StoredToken> updater) {
            return delegate.update(sessionId, updater);
        }

        private void awaitRelease() {
            try {
                assertTrue(release.await(AWAIT_SECONDS, TimeUnit.SECONDS),
                        "the test must release the parked leading caller");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while parking the leading caller", e);
            }
        }
    }
}
