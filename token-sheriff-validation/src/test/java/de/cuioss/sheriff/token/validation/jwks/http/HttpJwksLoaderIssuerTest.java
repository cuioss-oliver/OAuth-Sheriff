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

import de.cuioss.http.client.HttpLogMessages;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
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

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("HttpJwksLoader Issuer Identifier Tests")
@EnableMockWebServer
class HttpJwksLoaderIssuerTest {

    @Getter
    private final WellKnownDispatcher moduleDispatcher = new WellKnownDispatcher();

    private HttpJwksLoader jwksLoader;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        moduleDispatcher.setCallCounter(0);
    }

    @Test
    @DisplayName("Should return issuer identifier from well-known config when available")
    void shouldReturnIssuerFromWellKnownConfig(URIBuilder uriBuilder) {
        // Setup dispatcher with valid response
        moduleDispatcher.returnDefault();

        // Create HttpJwksLoader with well-known config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        // Get issuer identifier
        Optional<String> issuer = jwksLoader.getIssuerIdentifier();
        assertTrue(issuer.isPresent(), "Issuer should be present");
        assertNotNull(issuer.get(), "Issuer should not be null");
        assertTrue(issuer.get().startsWith("http"), "Issuer should be a URL string");
    }

    @Test
    @DisplayName("Should require issuer identifier for direct JWKS configuration")
    void shouldRequireIssuerForDirectJwks(URIBuilder uriBuilder) {
        // Attempt to create HttpJwksLoader with direct JWKS URL but no issuer - should fail
        HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder jwks = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(uriBuilder.addPathSegment("jwks").buildAsString());

        assertThrows(IllegalArgumentException.class, jwks::build, "Should throw exception when issuer is missing for direct JWKS configuration");
    }

    @Test
    @DisplayName("Should return empty when well-known config fails to load")
    void shouldReturnEmptyWhenWellKnownConfigUnhealthy(URIBuilder uriBuilder) {
        // Setup dispatcher to return error
        moduleDispatcher.returnError();

        // Create HttpJwksLoader with well-known config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        // Try to get issuer identifier - should return empty since config fails to load
        Optional<String> issuer = jwksLoader.getIssuerIdentifier();
        assertFalse(issuer.isPresent(), "Issuer should not be present when config fails to load");

        // After migration: ResilientHttpAdapter logs HTTP-111 (REQUEST_FAILED_MAX_ATTEMPTS) instead of HTTP-101
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                HttpLogMessages.WARN.REQUEST_FAILED_MAX_ATTEMPTS.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should return empty when issuer is missing from well-known response")
    void shouldReturnEmptyWhenIssuerMissingFromResponse(URIBuilder uriBuilder) {
        // Setup dispatcher with response missing issuer
        moduleDispatcher.returnMissingIssuer();

        // Create HttpJwksLoader with well-known config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        // Get issuer identifier - should return empty since issuer is missing
        Optional<String> issuer = jwksLoader.getIssuerIdentifier();
        assertFalse(issuer.isPresent(), "Issuer should not be present when missing from response");
    }

    @Test
    @DisplayName("Should cache issuer identifier after first retrieval")
    void shouldCacheIssuerIdentifier(URIBuilder uriBuilder) {
        // Setup dispatcher with valid response
        moduleDispatcher.returnDefault();

        // Create HttpJwksLoader with well-known config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        // First call - should load from server
        Optional<String> issuer1 = jwksLoader.getIssuerIdentifier();
        assertTrue(issuer1.isPresent());

        // Second call - should return cached value
        Optional<String> issuer2 = jwksLoader.getIssuerIdentifier();
        assertTrue(issuer2.isPresent());

        // Both should be the same
        assertEquals(issuer1.get(), issuer2.get());

        // Both should return same value after single request
        // Note: We can't directly check request count with the dispatcher
    }

    @Test
    @DisplayName("Should handle concurrent access to issuer identifier")
    void shouldHandleConcurrentAccessToIssuer(URIBuilder uriBuilder) throws Exception {
        // Setup dispatcher with valid response
        moduleDispatcher.returnDefault();

        // Create HttpJwksLoader with well-known config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        @SuppressWarnings("unchecked") Optional<String>[] results = new Optional[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                results[index] = jwksLoader.getIssuerIdentifier();
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // All threads should get the same issuer value
        for (int i = 0; i < threadCount; i++) {
            assertTrue(results[i].isPresent(), "Thread " + i + " should have received issuer");
            assertEquals(results[0].get(), results[i].get(), "All threads should receive the same issuer");
        }

        // All threads should get same issuer despite concurrent access
    }

    @Test
    @DisplayName("Should return empty when well-known config returns empty issuer")
    void shouldReturnEmptyWhenConfigReturnsEmptyIssuer() {
        // Create HttpJwksLoader with an invalid well-known URL
        // This will cause the config to fail and return empty issuer
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl("https://invalid.example.com/.well-known/openid-configuration")
                .build();

        jwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        // Get issuer identifier - should return empty
        Optional<String> issuer = jwksLoader.getIssuerIdentifier();
        assertFalse(issuer.isPresent(), "Issuer should not be present when config returns empty");
    }

    @Test
    @DisplayName("Should hard-fail discovery before fetching the advertised URL when the advertised issuer mismatches the configured trust anchor (M7)")
    void shouldHardFailWhenAdvertisedIssuerMismatches(URIBuilder uriBuilder) {
        // The discovery document advertises issuer == mock-server base URL; the configured trust
        // anchor is a different issuer, so discovery must hard-fail before the advertised jwks_uri
        // is fetched.
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .issuerIdentifier("https://trusted-issuer.example.com")
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        LoaderStatus status = jwksLoader.initJWKSLoader(securityEventCounter).join();

        assertAll("advertised-issuer gate (M7)",
                () -> assertEquals(LoaderStatus.ERROR, status,
                        "Discovery must hard-fail when the advertised issuer does not match the configured trust anchor"),
                () -> assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH),
                        "An advertised-issuer mismatch must be recorded exactly once"),
                () -> assertTrue(jwksLoader.getKeyInfo("any-kid").isEmpty(),
                        "No keys may be loaded from the advertised URL once the issuer gate fails"));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.ISSUER_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should tolerate a trailing-slash difference between advertised and configured issuer (M7)")
    void shouldTolerateTrailingSlashIssuerDifference(URIBuilder uriBuilder) {
        // The discovery document advertises issuer == base URL (no trailing slash); configuring the
        // same issuer with a trailing slash is a benign formatting variance, not a genuine mismatch.
        moduleDispatcher.returnDefault();
        String baseUrl = uriBuilder.buildAsString();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .allowLoopbackEgress(true)
                .allowInsecureHttp(true)
                .issuerIdentifier(baseUrl + "/")
                .wellKnownUrl(uriBuilder.addPathSegment(".well-known").addPathSegment("openid-configuration").buildAsString())
                .build();

        jwksLoader = new HttpJwksLoader(config);
        jwksLoader.initJWKSLoader(securityEventCounter).join();

        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH),
                "A trailing-slash difference must not be treated as an advertised-issuer mismatch");
    }
}
