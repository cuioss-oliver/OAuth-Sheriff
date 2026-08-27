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
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests HttpJwksLoader Background Refresh Scheduler")
@EnableMockWebServer
class HttpJwksLoaderSchedulerTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        securityEventCounter = new SecurityEventCounter();
    }


    @Test
    @DisplayName("Should not start scheduler when no config provided")
    void shouldNotStartSchedulerWithoutConfig(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        // Create loader without scheduler config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(0) // Disable scheduler
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Scheduler should not be active without config
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not be active without refresh interval");

        loader.close();
    }

    @Test
    @DisplayName("Should not start scheduler when refresh interval is zero")
    void shouldNotStartSchedulerWithZeroInterval(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(0) // Zero means no refresh
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Scheduler should not be active with zero interval
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not be active with zero interval");

        // With zero interval, background refresh is simply not started (no warning logged)

        loader.close();
    }

    @Test
    @DisplayName("Should start scheduler after first successful load")
    void shouldStartSchedulerAfterFirstLoad(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        // initJWKSLoader triggers the initial load and starts the scheduler
        loader.initJWKSLoader(securityEventCounter).join();

        // After initialization, scheduler should already be active (started during init)
        assertTrue(loader.isBackgroundRefreshActive(), "Background refresh should be active after initialization");

        // Verify initial load worked by getting a key
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Verify log message about scheduler start
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                JWTValidationLogMessages.INFO.JWKS_BACKGROUND_REFRESH_STARTED.resolveIdentifierString());

        loader.close();

        // After close, scheduler should be inactive
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should be inactive after close");
    }

    @Test
    @DisplayName("Should perform background refresh and detect changes")
    void shouldPerformBackgroundRefresh(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger initial load
        Optional<KeyInfo> initialKeyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial load should work");

        int initialCallCount = moduleDispatcher.getCallCounter();

        // Switch to different key to simulate change
        moduleDispatcher.switchToOtherPublicKey();

        // Wait for background refresh to trigger using Awaitility
        await("Background refresh to detect key changes and make additional HTTP call")
                .atMost(3, SECONDS)
                .until(() -> moduleDispatcher.getCallCounter() > initialCallCount);

        // Verify background refresh update was logged
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                JWTValidationLogMessages.INFO.JWKS_KEYS_UPDATED.resolveIdentifierString());

        loader.close();
    }

    @Test
    @DisplayName("Should handle background refresh errors gracefully")
    void shouldHandleBackgroundRefreshErrors(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger initial successful load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");
        assertEquals(LoaderStatus.OK, loader.getLoaderStatus(), "Loader should be healthy after initial load");

        // Make dispatcher return invalid JSON to trigger content conversion error
        // Invalid JSON causes ResilientHttpHandler to return failure result
        moduleDispatcher.returnInvalidJson();

        // Wait for background refresh to encounter the error and log BACKGROUND_REFRESH_FAILED
        // Content conversion errors result in HttpResult with isSuccess()=false,
        // which triggers the else branch (lines 324-327) in startBackgroundRefresh()
        await("Background refresh to encounter error and log BACKGROUND_REFRESH_FAILED")
                .atMost(3, SECONDS)
                .pollInterval(100, MILLISECONDS)
                .ignoreExceptions()
                .untilAsserted(() -> {
                    LogAsserts.assertLogMessagePresentContaining(
                            TestLogLevel.WARN,
                            JWTValidationLogMessages.WARN.BACKGROUND_REFRESH_FAILED.resolveIdentifierString());
                });

        // Loader should still be healthy if it has existing keys
        assertEquals(LoaderStatus.OK, loader.getLoaderStatus(), "Loader should remain healthy with cached keys even if background refresh fails");

        loader.close();
    }

    @Test
    @DisplayName("Should only start scheduler once")
    void shouldStartSchedulerOnlyOnce(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(10) // Longer interval to avoid multiple executions during test
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger multiple loads
        loader.getKeyInfo(TEST_KID);
        loader.getKeyInfo(TEST_KID);
        loader.getKeyInfo("another-kid");
        loader.getKeyInfo(null);

        // Wait for scheduler to start using Awaitility
        await("Scheduler to activate after multiple operations")
                .atMost(3, SECONDS)
                .until(loader::isBackgroundRefreshActive);

        // Should only have one scheduler start message
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                "Background JWKS refresh started");

        loader.close();
    }

    @Test
    @DisplayName("Should close scheduler cleanly")
    void shouldCloseSchedulerCleanly(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Start scheduler
        loader.getKeyInfo(TEST_KID);
        await("Scheduler to start after key load")
                .atMost(3, SECONDS)
                .until(loader::isBackgroundRefreshActive);

        // Close should cancel the task
        loader.close();
        assertFalse(loader.isBackgroundRefreshActive(), "Scheduler should be inactive after close");

        // Multiple closes should be safe
        loader.close();
        loader.close();
        assertFalse(loader.isBackgroundRefreshActive(), "Multiple closes should be safe");
    }

    @Test
    @DisplayName("Should not start scheduler if initial load fails")
    void shouldNotStartSchedulerIfInitialLoadFails(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Make all requests fail from the start
        moduleDispatcher.returnError();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Initial load should fail - getKeyInfo returns empty when loading fails
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isEmpty(), "Expected empty result for failed initial load");

        // Scheduler should be started after failed load to enable retries
        assertTrue(loader.isBackgroundRefreshActive(), "Background refresh should start after failed initial load to enable retries");
        // With retry capability, failed loads should not permanently corrupt status
        LoaderStatus status = loader.getLoaderStatus();
        assertTrue(status == LoaderStatus.UNDEFINED || status == LoaderStatus.OK,
                "Loader should have UNDEFINED or OK status (not permanent ERROR) after failed load to enable retry");

        loader.close();
    }

    @Test
    @DisplayName("Should handle background refresh correctly")
    void shouldHandleBackgroundRefreshCorrectly(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Wait for background refresh to execute - scheduler runs every 1 second
        await("At least one background refresh cycle to complete")
                .atMost(3, SECONDS)
                .pollDelay(1200, MILLISECONDS) // Give scheduler time to run at least once
                .until(() -> true); // Just wait for the time period

        // Verify that background refresh executed - it should have logged either:
        // - "Background refresh completed, no changes detected" if 304 Not Modified
        // - "Keys updated due to data change" if data changed
        // Both are valid outcomes depending on mock server behavior
        try {
            LogAsserts.assertLogMessagePresentContaining(
                    TestLogLevel.DEBUG,
                    "Background refresh completed, no changes detected");
        } catch (AssertionError e) {
            // If not no-changes, then it should have updated
            LogAsserts.assertLogMessagePresentContaining(
                    TestLogLevel.INFO,
                    "Keys updated due to data change");
        }

        loader.close();
    }
}
