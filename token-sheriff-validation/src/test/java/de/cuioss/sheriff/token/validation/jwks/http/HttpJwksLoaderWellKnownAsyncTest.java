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
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("HttpJwksLoader Well-Known Discovery Async Tests")
@EnableMockWebServer
class HttpJwksLoaderWellKnownAsyncTest {

    @Test
    @DisplayName("Constructor should not perform well-known discovery")
    void constructorShouldNotPerformWellKnownDiscovery() {
        // Create a well-known configuration with invalid URL to test constructor behavior
        String invalidWellKnownUrl = "https://invalid-host.example.com/.well-known/openid_configuration";

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(invalidWellKnownUrl)
                .build();

        // Measure constructor time
        long startTime = System.nanoTime();
        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            long constructorDurationNanos = System.nanoTime() - startTime;

            // Constructor must not perform well-known discovery (blocking I/O). The 200ms bound is
            // a proxy (real discovery of an invalid host would take seconds) that tolerates a GC
            // pause under parallel surefire forks; the UNDEFINED status below is the precise check.
            assertTrue(constructorDurationNanos < TimeUnit.MILLISECONDS.toNanos(200),
                    "Constructor should complete quickly without well-known discovery");

            assertEquals(LoaderStatus.UNDEFINED, loader.getLoaderStatus(),
                    "Status should remain UNDEFINED until initialization");
        }
    }

    @Test
    @DisplayName("Well-known discovery failure should be handled in async context")
    void wellKnownDiscoveryFailureShouldBeHandledAsync() {
        // Create configuration with invalid well-known URL
        String invalidWellKnownUrl = "https://invalid-host.example.com/.well-known/openid_configuration";

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(invalidWellKnownUrl)
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            SecurityEventCounter counter = new SecurityEventCounter();

            // Constructor should still be fast even with invalid well-known URL
            long startTime = System.nanoTime();
            try (HttpJwksLoader ignored = new HttpJwksLoader(config)) {
                long constructorDuration = System.nanoTime() - startTime;

                assertTrue(constructorDuration < TimeUnit.MILLISECONDS.toNanos(10),
                        "Constructor should be fast even with invalid well-known configuration");
            }

            // Async initialization should handle the failure
            CompletableFuture<LoaderStatus> initFuture = loader.initJWKSLoader(counter);

            // Wait for completion - should fail gracefully
            LoaderStatus status = initFuture.join();
            assertEquals(LoaderStatus.ERROR, status, "Initialization should fail with well-known discovery error");
            assertEquals(LoaderStatus.ERROR, loader.getLoaderStatus(), "Loader should be in ERROR status");

            // Verify appropriate error logging
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.JWKS_URI_RESOLUTION_FAILED.resolveIdentifierString());
        }
    }
}
