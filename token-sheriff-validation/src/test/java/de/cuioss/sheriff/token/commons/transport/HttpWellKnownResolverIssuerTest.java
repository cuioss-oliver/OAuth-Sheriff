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
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for issuer discovery in HttpWellKnownResolver.
 * <p>
 * Verifies that the issuer is correctly discovered from the well-known configuration
 * and handles various error scenarios appropriately.
 */
@EnableTestLogger
@DisplayName("HttpWellKnownResolver Issuer Discovery")
@EnableMockWebServer
class HttpWellKnownResolverIssuerTest {

    @Getter
    private final WellKnownDispatcher moduleDispatcher = new WellKnownDispatcher();

    private HttpWellKnownResolver resolver;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
    }

    @Test
    @DisplayName("Should return issuer from discovered configuration")
    void shouldReturnIssuerFromDiscoveredConfiguration(URIBuilder uriBuilder) {
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

        // Get issuer - should return the discovered issuer
        Optional<String> issuer = resolver.getIssuer();
        assertTrue(issuer.isPresent(), "Issuer should be discovered");
        assertEquals(baseUrl, issuer.get(), "Issuer should match expected URL");

        // Verify health status is OK after successful discovery
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus());

        // Verify well-known endpoint was called once
        assertEquals(1, moduleDispatcher.getCallCounter(), "Well-known endpoint should be called once");
    }

    @Test
    @DisplayName("Should return empty Optional when discovery fails")
    void shouldReturnEmptyOptionalWhenDiscoveryFails(URIBuilder uriBuilder) {
        // Setup dispatcher to return error
        moduleDispatcher.returnError();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Issuer should not be available when discovery fails
        Optional<String> issuer = resolver.getIssuer();
        assertFalse(issuer.isPresent(), "Issuer should not be available when discovery fails");

        // Health status should reflect error
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus());

        // Well-known endpoint should be called
        assertTrue(moduleDispatcher.getCallCounter() >= 1, "Well-known endpoint should be called at least once");
    }

    @Test
    @DisplayName("Should return empty Optional when issuer is missing")
    void shouldReturnEmptyOptionalWhenIssuerMissing(URIBuilder uriBuilder) {
        // Setup dispatcher with response missing issuer
        moduleDispatcher.returnMissingIssuer();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Issuer should not be available when missing from response
        Optional<String> issuer = resolver.getIssuer();
        assertFalse(issuer.isPresent(), "Issuer should not be available when missing from response");

        // Health status should be ERROR since issuer is required
        assertEquals(LoaderStatus.ERROR, resolver.getLoaderStatus());
    }

    @Test
    @DisplayName("Should cache discovery results")
    void shouldCacheDiscoveryResults(URIBuilder uriBuilder) {
        // Setup well-known dispatcher to return valid response
        moduleDispatcher.returnDefault();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Get issuer multiple times
        Optional<String> issuer1 = resolver.getIssuer();
        Optional<String> issuer2 = resolver.getIssuer();
        Optional<String> issuer3 = resolver.getIssuer();

        // All should return the same result
        assertTrue(issuer1.isPresent());
        assertTrue(issuer2.isPresent());
        assertTrue(issuer3.isPresent());
        assertEquals(issuer1.get(), issuer2.get(), "Multiple calls should return same issuer");
        assertEquals(issuer2.get(), issuer3.get(), "Multiple calls should return same issuer");

        // Well-known should only be called once (cached)
        assertEquals(1, moduleDispatcher.getCallCounter(), "Well-known endpoint should be called once (cached)");
    }

    @Test
    @DisplayName("Should handle invalid issuer appropriately")
    void shouldHandleInvalidIssuerAppropriately(URIBuilder uriBuilder) {
        // Setup dispatcher with invalid issuer
        moduleDispatcher.returnInvalidIssuer();

        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Should still return the issuer even if it's invalid (validation is not the resolver's job)
        Optional<String> issuer = resolver.getIssuer();
        assertTrue(issuer.isPresent(), "Invalid issuer should still be returned");
        assertTrue(issuer.get().contains("invalid-"), "Should contain the invalid issuer");

        // Health status should be OK for successful HTTP response (content validation is separate)
        assertEquals(LoaderStatus.OK, resolver.getLoaderStatus());
    }

    @Test
    @DisplayName("Should work with minimal configuration")
    void shouldWorkWithMinimalConfiguration(URIBuilder uriBuilder) {
        // Setup dispatcher to return only required fields
        moduleDispatcher.returnOnlyRequiredFields();

        String baseUrl = uriBuilder.buildAsString();
        String wellKnownUrl = uriBuilder.addPathSegment(".well-known")
                .addPathSegment("openid-configuration").buildAsString();

        WellKnownConfig config = WellKnownConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(wellKnownUrl)
                .retryConfig(RetryConfig.builder().maxAttempts(1).build())
                .build();

        resolver = config.createResolver(new SecurityEventCounter());

        // Should still work with minimal configuration
        Optional<String> issuer = resolver.getIssuer();
        assertTrue(issuer.isPresent(), "Issuer should be available from minimal config");
        assertEquals(baseUrl, issuer.get(), "Issuer should match expected URL");

        // JWKS URI should also be available
        Optional<String> jwksUri = resolver.getJwksUri();
        assertTrue(jwksUri.isPresent(), "JWKS URI should be available from minimal config");

        // WellKnownResult should be available with core fields
        Optional<WellKnownResult> result = resolver.getWellKnownResult();
        assertTrue(result.isPresent(), "WellKnownResult should be available");
    }
}
