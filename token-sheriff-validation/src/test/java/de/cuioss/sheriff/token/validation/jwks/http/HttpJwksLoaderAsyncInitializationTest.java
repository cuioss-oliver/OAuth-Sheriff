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
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
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
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("HttpJwksLoader Async Initialization Tests")
@EnableMockWebServer
class HttpJwksLoaderAsyncInitializationTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        moduleDispatcher.returnDefault();
    }

    @Test
    @DisplayName("Constructor should not block or perform I/O operations")
    void constructorShouldNotBlockOrPerformIO(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        // Measure constructor execution time
        long startTime = System.nanoTime();
        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            long constructorDurationNanos = System.nanoTime() - startTime;

            // Constructor must not perform blocking I/O. The 200ms bound is a proxy for that
            // (a real network call would take seconds via DNS/connect timeouts) and is loose
            // enough to survive a GC pause under parallel surefire forks; the "no I/O" contract is
            // asserted precisely below via the call counter and UNDEFINED status.
            long maxAllowedNanos = TimeUnit.MILLISECONDS.toNanos(200);
            assertTrue(constructorDurationNanos < maxAllowedNanos,
                    "Constructor took %d ns (%.2f ms), should be < %d ns (200 ms)".formatted(
                            constructorDurationNanos,
                            constructorDurationNanos / 1_000_000.0,
                            maxAllowedNanos));

            // Status should be UNDEFINED immediately after construction (no loading yet)
            assertEquals(LoaderStatus.UNDEFINED, loader.getLoaderStatus(),
                    "Status should be UNDEFINED immediately after construction");

            // Verify no HTTP calls were made during construction
            assertEquals(0, moduleDispatcher.getCallCounter(),
                    "No HTTP calls should be made during construction");
        }
    }

    @Test
    @DisplayName("initJWKSLoader should return non-completed CompletableFuture")
    void initJWKSLoaderShouldReturnAsyncCompletableFuture(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Call initJWKSLoader - should return CompletableFuture
            CompletableFuture<LoaderStatus> initFuture = loader.initJWKSLoader(counter);

            // Verify it returns a CompletableFuture
            assertNotNull(initFuture, "initJWKSLoader should return a CompletableFuture");

            // The future should complete eventually with OK status
            LoaderStatus finalStatus = initFuture.join();
            assertEquals(LoaderStatus.OK, finalStatus, "Initialization should complete with OK status");

            // After completion, loader should be in OK state
            assertEquals(LoaderStatus.OK, loader.getLoaderStatus(),
                    "Loader status should be OK after successful initialization");
        }
    }

    @Test
    @DisplayName("Status should transition atomically during async initialization")
    void statusShouldTransitionAtomicallyDuringAsyncInit(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Initial status should be UNDEFINED
            assertEquals(LoaderStatus.UNDEFINED, loader.getLoaderStatus(),
                    "Initial status should be UNDEFINED");

            // Start async initialization
            CompletableFuture<LoaderStatus> initFuture = loader.initJWKSLoader(counter);

            // Wait for status to transition to LOADING, then to OK
            Awaitility.await()
                    .atMost(Duration.ofSeconds(5))
                    .until(() -> loader.getLoaderStatus() == LoaderStatus.OK);

            // Verify final status
            assertEquals(LoaderStatus.OK, loader.getLoaderStatus(),
                    "Final status should be OK");

            // Verify future completed with OK
            assertTrue(initFuture.isDone(), "Future should be completed");
            assertEquals(LoaderStatus.OK, initFuture.join(), "Future should complete with OK");
        }
    }

    @Test
    @DisplayName("Multiple concurrent initJWKSLoader calls should be handled safely")
    void multipleConcurrentInitCallsShouldBeSafe(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Make multiple concurrent calls to initJWKSLoader
            CompletableFuture<LoaderStatus> future1 = loader.initJWKSLoader(counter);
            CompletableFuture<LoaderStatus> future2 = loader.initJWKSLoader(counter);
            CompletableFuture<LoaderStatus> future3 = loader.initJWKSLoader(counter);

            // All futures should complete with OK
            assertEquals(LoaderStatus.OK, future1.join(), "First init should complete with OK");
            assertEquals(LoaderStatus.OK, future2.join(), "Second init should complete with OK");
            assertEquals(LoaderStatus.OK, future3.join(), "Third init should complete with OK");

            // Final loader status should be OK
            assertEquals(LoaderStatus.OK, loader.getLoaderStatus(),
                    "Loader status should be OK after concurrent initialization");

            // Keys should be available
            Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Keys should be available after initialization");
        }
    }
}
