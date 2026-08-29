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
package de.cuioss.sheriff.token.integration.client;

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.sheriff.token.validation.TokenValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins {@link TokenLifecycleManager}'s per-session single-flight against the real Keycloak container.
 * <p>
 * A refresh token is a one-shot credential under rotation: if two proactive refreshes for the same
 * session both reach the token endpoint, the second presents an already-superseded token and the
 * client's own {@code RefreshTokenFamily} classifies a benign race as theft — revoking the family and
 * logging the user out. {@code TokenLifecycleManager} defends against that with a per-session
 * {@code CompletableFuture}: the first caller installs it, and a concurrent caller shares that one
 * in-flight rotation rather than redeeming again.
 * <p>
 * The overlap is <em>constructed</em>, not hoped for. The first caller is parked inside the refresh
 * flow — after the single-flight future is installed, before the token endpoint is reached — and the
 * second caller is only released into {@code refresh(...)} once the first is provably parked there.
 * Without the collapse the second caller would redeem the same token a second time and the exchange
 * count would be two, so the assertion below can genuinely fail.
 */
@DisplayName("TokenLifecycleManager single-flight refresh against real Keycloak")
class RefreshSingleFlightSpecIT extends BaseIntegrationTest {

    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    /** Bounded wait for a caller to reach its expected park; generous, but never unbounded. */
    private static final Duration HANDOVER_BUDGET = Duration.ofSeconds(30);

    @Test
    @DisplayName("Should collapse two concurrent refreshes onto one redemption of the refresh token")
    void shouldCollapseConcurrentRefreshesOntoOneRedemption() throws Exception {
        ClientConfiguration configuration =
                RefreshEngineSupport.clientConfiguration(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        TokenValidator validator = RefreshEngineSupport.tokenValidator();
        TokenValidationBridge accessBridge = RefreshEngineSupport.accessTokenBridge(validator);
        IdTokenValidationBridge idBridge = RefreshEngineSupport.idTokenBridge(validator);
        ClientAuthentication clientAuthentication = RefreshEngineSupport.clientAuthentication(configuration);
        RevocationClient revocationClient = new RevocationClient(configuration);
        ProviderMetadata metadata = RefreshEngineSupport.providerMetadata();

        CountDownLatch firstCallerParked = new CountDownLatch(1);
        CountDownLatch releaseFirstCaller = new CountDownLatch(1);
        ParkingRefreshFlow refreshFlow = new ParkingRefreshFlow(configuration, accessBridge,
                clientAuthentication, firstCallerParked, releaseFirstCaller);

        TokenLifecycleManager manager =
                new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        String sessionId = UUID.randomUUID().toString();
        StoredToken original = acquireBundle();
        manager.store(sessionId, original);

        ExecutorService callers = Executors.newFixedThreadPool(2);
        AtomicReference<Thread> secondCaller = new AtomicReference<>();
        try {
            Future<Optional<StoredToken>> firstResult;
            Future<Optional<StoredToken>> secondResult;
            try {
                firstResult = callers.submit(() -> manager.refresh(sessionId, metadata, refreshFlow,
                        revocationClient, idBridge, clientAuthentication));
                assertTrue(firstCallerParked.await(HANDOVER_BUDGET.toSeconds(), TimeUnit.SECONDS),
                        "the first caller must reach the refresh flow, having installed the single-flight future");

                secondResult = callers.submit(() -> {
                    secondCaller.set(Thread.currentThread());
                    return manager.refresh(sessionId, metadata, refreshFlow, revocationClient, idBridge,
                            clientAuthentication);
                });
                // The second caller can only reach WAITING by joining the first caller's in-flight future:
                // its own token exchange would be a blocking socket read (RUNNABLE), and reaching the flow
                // at all would have bumped the exchange count asserted below.
                await("second caller collapsed onto the in-flight rotation")
                        .atMost(HANDOVER_BUDGET)
                        .pollInterval(Duration.ofMillis(50))
                        .until(() -> secondCaller.get() != null
                                && secondCaller.get().getState() == Thread.State.WAITING);
            } finally {
                releaseFirstCaller.countDown();
            }

            Optional<StoredToken> firstObserved =
                    firstResult.get(HANDOVER_BUDGET.toSeconds(), TimeUnit.SECONDS);
            Optional<StoredToken> secondObserved =
                    secondResult.get(HANDOVER_BUDGET.toSeconds(), TimeUnit.SECONDS);
            StoredToken refreshed = firstObserved
                    .orElseThrow(() -> new AssertionError("the first caller must observe the refreshed bundle"));

            assertAll("single-flight collapse",
                    () -> assertEquals(1, refreshFlow.exchanges(),
                            "the refresh token must be redeemed exactly once across both concurrent callers"),
                    () -> assertEquals(firstObserved, secondObserved,
                            "the second caller must observe the first caller's rotation, not one of its own"),
                    () -> assertNotEquals(original.refreshToken(), refreshed.refreshToken(),
                            "the single rotation must still have advanced the session's refresh token"),
                    () -> assertEquals(Optional.of(refreshed), manager.get(sessionId),
                            "the store must hold exactly the bundle both callers observed"));
        } finally {
            callers.shutdownNow();
        }
    }

    private static StoredToken acquireBundle() {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");
        assertNotNull(acquired.expiresInSeconds(), "Keycloak must report the access-token lifetime");
        return new StoredToken(acquired.accessToken(), acquired.refreshToken(), acquired.idToken(),
                null, Instant.now().plusSeconds(acquired.expiresInSeconds()));
    }

    /**
     * Production {@link RefreshFlow} that counts its exchanges and parks its <em>first</em> caller until
     * released, so a second caller is guaranteed to arrive while the first rotation is still in flight.
     * <p>
     * The park sits inside {@code refresh(...)}, which the lifecycle manager reaches only after it has
     * installed the session's single-flight future — exactly the window the collapse must cover. Apart
     * from the park, the exchange is the unmodified production one.
     */
    private static final class ParkingRefreshFlow extends RefreshFlow {

        private final AtomicInteger exchanges = new AtomicInteger();
        private final CountDownLatch parked;
        private final CountDownLatch release;

        ParkingRefreshFlow(ClientConfiguration configuration, TokenValidationBridge validationBridge,
                ClientAuthentication clientAuthentication, CountDownLatch parked, CountDownLatch release) {
            super(configuration, new TokenEndpointClient(configuration), validationBridge,
                    clientAuthentication);
            this.parked = parked;
            this.release = release;
        }

        @Override
        public RotationResult refresh(ProviderMetadata metadata, String refreshToken) {
            if (exchanges.incrementAndGet() == 1) {
                parked.countDown();
                awaitRelease();
            }
            return super.refresh(metadata, refreshToken);
        }

        private void awaitRelease() {
            try {
                if (!release.await(HANDOVER_BUDGET.toSeconds(), TimeUnit.SECONDS)) {
                    throw new IllegalStateException("the first caller was never released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while parking the first refresh caller", e);
            }
        }

        int exchanges() {
            return exchanges.get();
        }
    }
}
