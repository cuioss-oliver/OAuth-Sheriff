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
package de.cuioss.sheriff.token.validation.jwks.http;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("HttpJwksLoader Lock-Free Status Check Tests")
@EnableMockWebServer
class HttpJwksLoaderLockFreeStatusTest {

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        moduleDispatcher.returnDefault();
    }

    @Test
    @DisplayName("getLoaderStatus should be lock-free under high contention")
    void getLoaderStatusShouldBeLockFreeUnderHighContention(URIBuilder uriBuilder) throws Exception {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("lock-free-test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Start async initialization to get loader into active state
            CompletableFuture<LoaderStatus> initFuture = loader.initJWKSLoader(counter);

            int threadCount = 100;
            try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
                CyclicBarrier barrier = new CyclicBarrier(threadCount);
                CountDownLatch endLatch = new CountDownLatch(threadCount);
                AtomicInteger successCount = new AtomicInteger(0);
                AtomicReference<BrokenBarrierException> barrierException = new AtomicReference<>();
                AtomicReference<InterruptedException> interruptedException = new AtomicReference<>();

                // Launch 100 threads that will hammer getLoaderStatus() simultaneously
                for (int i = 0; i < threadCount; i++) {
                    executor.submit(() -> {
                        try {
                            // Synchronize all threads to start at exactly the same time
                            barrier.await();

                            // Each thread calls getLoaderStatus() multiple times rapidly
                            for (int j = 0; j < 50; j++) {
                                LoaderStatus status = loader.getLoaderStatus();
                                assertNotNull(status, "Status should never be null");
                                // Status should be one of the valid enum values
                                assertTrue(
                                        status == LoaderStatus.UNDEFINED ||
                                                status == LoaderStatus.LOADING ||
                                                status == LoaderStatus.OK ||
                                                status == LoaderStatus.ERROR,
                                        "Status should be a valid LoaderStatus value: " + status
                                );
                            }
                            successCount.incrementAndGet();

                        } catch (BrokenBarrierException e) {
                            barrierException.compareAndSet(null, e);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            interruptedException.compareAndSet(null, e);
                        } finally {
                            endLatch.countDown();
                        }
                    });
                }

                // Wait for all threads to complete
                boolean completed = endLatch.await(10, TimeUnit.SECONDS);
                executor.shutdown();

                assertTrue(completed, "All threads should complete within timeout");
                assertNull(barrierException.get(), "No barrier exceptions should occur during concurrent access");
                assertNull(interruptedException.get(), "No interruption exceptions should occur during concurrent access");
                assertEquals(threadCount, successCount.get(), "All threads should successfully read status");

                // Ensure initialization completes properly
                LoaderStatus finalStatus = initFuture.join();
                assertTrue(finalStatus == LoaderStatus.OK || finalStatus == LoaderStatus.ERROR,
                        "Initialization should complete with OK or ERROR status");
            }
        }
    }

    @Test
    @DisplayName("Status transitions should be atomic and consistent")
    void statusTransitionsShouldBeAtomicAndConsistent(URIBuilder uriBuilder) throws Exception {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("atomic-transition-test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Initial status should be UNDEFINED
            assertEquals(LoaderStatus.UNDEFINED, loader.getLoaderStatus(),
                    "Initial status should be UNDEFINED");

            int observerThreadCount = 50;
            try (ExecutorService observerExecutor = Executors.newFixedThreadPool(observerThreadCount)) {
                CountDownLatch observerLatch = new CountDownLatch(observerThreadCount);
                AtomicInteger undefinedObservations = new AtomicInteger(0);
                AtomicInteger loadingObservations = new AtomicInteger(0);
                AtomicInteger okObservations = new AtomicInteger(0);
                AtomicInteger errorObservations = new AtomicInteger(0);
                AtomicInteger invalidTransitions = new AtomicInteger(0);

                // Start multiple threads observing status transitions
                for (int i = 0; i < observerThreadCount; i++) {
                    observerExecutor.submit(() -> {
                        try {
                            LoaderStatus previousStatus = null;

                            // Observe status changes for up to 5 seconds
                            long endTime = System.currentTimeMillis() + 5000;
                            while (System.currentTimeMillis() < endTime) {
                                LoaderStatus currentStatus = loader.getLoaderStatus();

                                // Count observations of each status
                                switch (currentStatus) {
                                    case UNDEFINED -> undefinedObservations.incrementAndGet();
                                    case LOADING -> loadingObservations.incrementAndGet();
                                    case OK -> okObservations.incrementAndGet();
                                    case ERROR -> errorObservations.incrementAndGet();
                                }

                                // Check for invalid transitions
                                // Valid transitions: UNDEFINED -> LOADING, LOADING -> OK/ERROR
                                // Invalid: OK -> anything, ERROR -> anything, LOADING -> UNDEFINED
                                if ((previousStatus == LoaderStatus.OK && currentStatus != LoaderStatus.OK) ||
                                        (previousStatus == LoaderStatus.ERROR && currentStatus != LoaderStatus.ERROR) ||
                                        (previousStatus == LoaderStatus.LOADING && currentStatus == LoaderStatus.UNDEFINED)) {
                                    invalidTransitions.incrementAndGet();
                                }

                                previousStatus = currentStatus;

                                // Brief pause to allow other threads to observe
                                Awaitility.await().pollDelay(Duration.ofMillis(1)).until(() -> true);
                            }
                        } finally {
                            observerLatch.countDown();
                        }
                    });
                }

                // Start async initialization after observers are running
                Awaitility.await().pollDelay(Duration.ofMillis(100)).until(() -> true); // Give observers time to start
                CompletableFuture<LoaderStatus> initFuture = loader.initJWKSLoader(counter);

                // Wait for initialization to complete
                LoaderStatus finalStatus = initFuture.join();

                // Wait for all observer threads to complete
                boolean observersCompleted = observerLatch.await(10, TimeUnit.SECONDS);

                assertTrue(observersCompleted, "All observer threads should complete");
                assertEquals(0, invalidTransitions.get(),
                        "No invalid status transitions should be observed");

                // Verify expected transition pattern
                assertTrue(undefinedObservations.get() > 0,
                        "Should observe UNDEFINED status");
                assertTrue(okObservations.get() > 0 || errorObservations.get() > 0,
                        "Should observe final status (OK or ERROR)");
                assertTrue(finalStatus == LoaderStatus.OK || finalStatus == LoaderStatus.ERROR,
                        "Final status should be OK or ERROR");

                // If successful, should have observed LOADING state
                if (finalStatus == LoaderStatus.OK) {
                    assertTrue(loadingObservations.get() > 0,
                            "Should observe LOADING status during successful initialization");
                }
            }
        }
    }

    @Test
    @DisplayName("Concurrent status checks during multiple initializations should be safe")
    void concurrentStatusChecksDuringMultipleInitializationsShouldBeSafe(URIBuilder uriBuilder) throws Exception {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("multi-init-test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            int initThreadCount = 10;
            int statusCheckThreadCount = 50;
            try (ExecutorService executor = Executors.newFixedThreadPool(initThreadCount + statusCheckThreadCount)) {
                CountDownLatch startLatch = new CountDownLatch(1);
                CountDownLatch endLatch = new CountDownLatch(initThreadCount + statusCheckThreadCount);
                AtomicInteger statusCheckSuccesses = new AtomicInteger(0);
                AtomicInteger initSuccesses = new AtomicInteger(0);
                AtomicReference<InterruptedException> initInterruptedException = new AtomicReference<>();

                // Launch multiple threads calling initJWKSLoader concurrently
                for (int i = 0; i < initThreadCount; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();

                            CompletableFuture<LoaderStatus> future = loader.initJWKSLoader(counter);
                            LoaderStatus result = future.join();
                            assertTrue(result == LoaderStatus.OK || result == LoaderStatus.ERROR,
                                    "Init should complete with OK or ERROR");
                            initSuccesses.incrementAndGet();

                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            initInterruptedException.compareAndSet(null, e);
                        } finally {
                            endLatch.countDown();
                        }
                    });
                }

                // Launch many threads continuously checking status
                for (int i = 0; i < statusCheckThreadCount; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();

                            // Check status repeatedly for 3 seconds
                            long endTime = System.currentTimeMillis() + 3000;
                            while (System.currentTimeMillis() < endTime) {
                                LoaderStatus status = loader.getLoaderStatus();
                                assertNotNull(status, "Status should never be null");

                                // Use Awaitility instead of Thread.sleep for better testing
                                Awaitility.await().pollDelay(Duration.ofMillis(1)).until(() -> true);
                            }
                            statusCheckSuccesses.incrementAndGet();

                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            endLatch.countDown();
                        }
                    });
                }

                // Start all threads simultaneously
                startLatch.countDown();

                // Wait for completion
                boolean completed = endLatch.await(15, TimeUnit.SECONDS);

                assertTrue(completed, "All threads should complete");
                assertNull(initInterruptedException.get(), "No interruption exceptions should occur");
                assertTrue(initSuccesses.get() > 0, "Some initializations should succeed");
                assertEquals(statusCheckThreadCount, statusCheckSuccesses.get(),
                        "All status check threads should complete successfully");
            }
        }
    }
}
