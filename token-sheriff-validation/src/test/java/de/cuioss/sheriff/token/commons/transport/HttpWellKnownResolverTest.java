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
package de.cuioss.sheriff.token.commons.transport;

import de.cuioss.http.client.adapter.RetryConfig;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.test.dispatcher.WellKnownDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link HttpWellKnownResolver} with MockWebServer integration.
 * <p>
 * These tests verify the resolver works correctly with real HTTP operations,
 * including timing variants, error scenarios, and caching behavior.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@DisplayName("HttpWellKnownResolver MockWebServer Tests")
@EnableMockWebServer
class HttpWellKnownResolverTest {

    @Getter
    private final WellKnownDispatcher moduleDispatcher = new WellKnownDispatcher();

    private HttpWellKnownResolver resolver;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
    }

    @Test
    @DisplayName("Should successfully resolve JWKS URI from well-known endpoint")
    void shouldSuccessfullyResolveJwksUri(URIBuilder uriBuilder) {
        // Setup well-known dispatcher to return valid response
        moduleDispatcher.returnDefault();

        String baseUrl = uriBuilder.buildAsString();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        String expectedJwksUri = baseUrl + "/oidc/jwks.json";

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Test JWKS URI resolution
        Optional<String> jwksUri = resolver.getJwksUri();
        assertTrue(jwksUri.isPresent(), "JWKS URI should be discovered");
        assertEquals(expectedJwksUri, jwksUri.get(), "JWKS URI should match expected URL");

        // Verify health status is OK after successful resolution
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus());

        // Verify well-known endpoint was called once
        assertEquals(1, moduleDispatcher.getCallCounter(), "Well-known endpoint should be called once");
    }

    @Test
    @DisplayName("Should successfully resolve issuer from well-known endpoint")
    void shouldSuccessfullyResolveIssuer(URIBuilder uriBuilder) {
        // Setup well-known dispatcher to return valid response
        moduleDispatcher.returnDefault();

        String baseUrl = uriBuilder.buildAsString();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Test issuer resolution
        Optional<String> issuer = resolver.getIssuer();
        assertTrue(issuer.isPresent(), "Issuer should be discovered");
        assertEquals(baseUrl, issuer.get(), "Issuer should match base URL");

        // Verify health status is OK
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus());
    }

    @Test
    @DisplayName("Should resolve multiple endpoints correctly")
    void shouldResolveMultipleEndpoints(URIBuilder uriBuilder) {
        // Setup well-known dispatcher to return valid response
        moduleDispatcher.returnDefault();

        String baseUrl = uriBuilder.buildAsString();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Test multiple endpoint resolutions
        Optional<String> issuer = resolver.getIssuer();
        Optional<String> jwksUri = resolver.getJwksUri();
        Optional<WellKnownResult> wellKnownResult = resolver.getWellKnownResult();

        // Core endpoints should be available
        assertTrue(issuer.isPresent(), "Issuer should be available");
        assertTrue(jwksUri.isPresent(), "JWKS URI should be available");
        assertTrue(wellKnownResult.isPresent(), "WellKnownResult should be available");

        // Verify endpoint URLs
        assertEquals(baseUrl, issuer.get());
        assertEquals(baseUrl + "/oidc/jwks.json", jwksUri.get());

        // Should only call the well-known endpoint once due to caching
        assertEquals(1, moduleDispatcher.getCallCounter(), "Well-known endpoint should be called once (cached)");
    }

    @Test
    @DisplayName("Should handle error responses gracefully")
    void shouldHandleErrorResponsesGracefully(URIBuilder uriBuilder) {
        // Setup dispatcher to return error
        moduleDispatcher.returnError();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // All endpoint resolutions should return empty
        assertFalse(resolver.getJwksUri().isPresent(), "JWKS URI should not be available on error");
        assertFalse(resolver.getIssuer().isPresent(), "Issuer should not be available on error");
        assertFalse(resolver.getWellKnownResult().isPresent(), "WellKnownResult should not be available on error");

        // Health status should reflect error
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus());

        // Well-known endpoint should be called
        assertTrue(moduleDispatcher.getCallCounter() >= 1, "Well-known endpoint should be called at least once");
    }

    @Test
    @DisplayName("Should handle missing JWKS URI gracefully")
    void shouldHandleMissingJwksUriGracefully(URIBuilder uriBuilder) {
        // Setup dispatcher with response missing JWKS URI
        moduleDispatcher.returnMissingJwksUri();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // JWKS URI should not be available
        assertFalse(resolver.getJwksUri().isPresent(), "JWKS URI should not be available when missing from response");

        // No endpoints should be available since JWKS URI is a required field
        assertFalse(resolver.getIssuer().isPresent(), "Issuer should not be available when JWKS URI is missing (invalid config)");

        // Health status should be ERROR since JWKS URI is required for JWT validation
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus());
    }

    @Test
    @DisplayName("Should provide access to complete WellKnownResult")
    void shouldProvideAccessToCompleteWellKnownResult(URIBuilder uriBuilder) {
        // Setup well-known dispatcher to return valid response
        moduleDispatcher.returnDefault();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Test complete result access
        Optional<WellKnownResult> result = resolver.getWellKnownResult();
        assertTrue(result.isPresent(), "WellKnownResult should be available");

        var wellKnown = result.get();
        assertNotNull(wellKnown.getIssuer(), "Issuer should be present in result");
        assertNotNull(wellKnown.getJwksUri(), "JWKS URI should be present in result");
    }

    @Test
    @DisplayName("Should reuse a cached successful discovery within the bounded TTL (M2)")
    void shouldReuseCachedSuccessWithinTtl(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        WellKnownConfig config = WellKnownConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        resolver = config.createResolver(new SecurityEventCounter());

        assertTrue(resolver.getJwksUri().isPresent(), "First discovery should succeed");
        assertTrue(resolver.getIssuer().isPresent(), "Second lookup should be served from cache");
        assertTrue(resolver.getWellKnownResult().isPresent(), "Third lookup should be served from cache");

        assertEquals(1, moduleDispatcher.getCallCounter(),
                "A successful discovery must be cached within its bounded TTL — only one network call");
    }

    @Test
    @DisplayName("Should revalidate a successful discovery once the bounded TTL elapses (M2)")
    void shouldRevalidateAfterTtlElapses(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        WellKnownConfig config = WellKnownConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        // A zero TTL makes every cached success immediately stale, so each lookup revalidates.
        resolver = new HttpWellKnownResolver(config, new SecurityEventCounter(), Duration.ZERO);

        assertTrue(resolver.getJwksUri().isPresent(), "First discovery should succeed");
        assertTrue(resolver.getJwksUri().isPresent(), "Second discovery should succeed after revalidation");

        assertEquals(2, moduleDispatcher.getCallCounter(),
                "An elapsed bounded TTL must trigger revalidation — the endpoint is fetched again");
    }

    @Test
    @DisplayName("Should not pin a failed discovery — recovers on the next call (M2)")
    void shouldNotPinFailedDiscovery(URIBuilder uriBuilder) {
        moduleDispatcher.returnError();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        WellKnownConfig config = WellKnownConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        resolver = config.createResolver(new SecurityEventCounter());

        assertFalse(resolver.getJwksUri().isPresent(), "Discovery should fail while the endpoint returns errors");
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus(), "Status should reflect the failure");

        // The endpoint recovers; a previously failed discovery must not be pinned.
        moduleDispatcher.returnDefault();
        assertTrue(resolver.getJwksUri().isPresent(),
                "A previously failed discovery must not be cached — it recovers once the endpoint is healthy");
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus(), "Status should recover to OK");
    }

    @Test
    @DisplayName("Should reject a loopback discovery endpoint before any fetch when egress is not opted in (C1)")
    void shouldRejectLoopbackDiscoveryBeforeFetch(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        // allowInsecureHttp(true) only permits the cleartext MockWebServer URL; allowLoopbackEgress
        // is deliberately left at its secure default (false) so the egress guard rejects loopback.
        WellKnownConfig config = WellKnownConfig.builder()
                .allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        resolver = config.createResolver(new SecurityEventCounter());

        assertFalse(resolver.getJwksUri().isPresent(),
                "Discovery must be blocked when its host resolves to a loopback address");
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus(),
                "A blocked discovery must surface as ERROR");
        assertEquals(0, moduleDispatcher.getCallCounter(),
                "The egress guard must reject the discovery endpoint BEFORE any fetch is issued");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "SSRF egress guard blocked");
    }

    @Test
    @DisplayName("Should perform exactly one HTTP load under concurrent first-access callers (single-flight)")
    void shouldLoadOnceUnderConcurrentAccess(URIBuilder uriBuilder) throws Exception {
        moduleDispatcher.returnDefault();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        WellKnownConfig config = WellKnownConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        resolver = config.createResolver(new SecurityEventCounter());

        int threadCount = 16;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger present = new AtomicInteger();
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                futures.add(executor.submit(() -> {
                    ready.countDown();
                    try {
                        // Release all threads simultaneously to maximise the race on first access.
                        start.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    if (resolver.getJwksUri().isPresent()) {
                        present.incrementAndGet();
                    }
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS), "All worker threads should reach the barrier");
            start.countDown();
            for (Future<?> future : futures) {
                assertDoesNotThrow(() -> future.get(10, TimeUnit.SECONDS));
            }
        } finally {
            executor.shutdownNow();
        }

        assertEquals(threadCount, present.get(), "Every concurrent caller must observe the discovered JWKS URI");
        assertEquals(1, moduleDispatcher.getCallCounter(),
                "Concurrent first-access callers must trigger exactly one HTTP load — the single-flight gate must hold");
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus(), "Status must settle to OK after the single load");
    }

    @Test
    @DisplayName("Should fetch the discovery endpoint when loopback egress is explicitly opted in (C1)")
    void shouldFetchLoopbackDiscoveryWhenOptedIn(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();
        WellKnownConfig config = WellKnownConfig.builder()
                .allowInsecureHttp(true)
                .allowLoopbackEgress(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();
        resolver = config.createResolver(new SecurityEventCounter());

        assertTrue(resolver.getJwksUri().isPresent(),
                "The explicit loopback opt-in must permit the discovery fetch");
        assertEquals(1, moduleDispatcher.getCallCounter(),
                "With the opt-in the discovery endpoint is fetched exactly once");
    }
}
