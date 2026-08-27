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

import static org.junit.jupiter.api.Assertions.assertFalse;

@EnableTestLogger
@DisplayName("HttpJwksLoader Failure Tests")
@EnableMockWebServer
class HttpJwksLoaderFailureTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        moduleDispatcher.returnDefault();
        securityEventCounter = new SecurityEventCounter();
    }

    @Test
    @DisplayName("Should log JWKS_LOAD_FAILED when HTTP connection cannot be established")
    void shouldLogJwksLoadFailedWhenHttpConnectionFails() {
        // Create loader with invalid URL to simulate connection failure
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl("http://invalid-host-that-does-not-exist:9999/jwks")
                .issuerIdentifier("test-issuer")
                .build();

        try (HttpJwksLoader failingLoader = new HttpJwksLoader(config)) {
            // Wait for async initialization to complete (even if it fails)
            failingLoader.initJWKSLoader(securityEventCounter).join();

            // Try to get a key, which should fail
            Optional<KeyInfo> keyInfo = failingLoader.getKeyInfo(TEST_KID);
            assertFalse(keyInfo.isPresent(), "Key info should not be present when connection fails");

            // Verify the appropriate error was logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.JWKS_LOAD_FAILED.resolveIdentifierString());

            // cui-http 2.0.0 classifies an unreachable host as a network error and logs
            // REQUEST_FAILED_MAX_ATTEMPTS at WARN once retries are exhausted.
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    HttpLogMessages.WARN.REQUEST_FAILED_MAX_ATTEMPTS.resolveIdentifierString());
        }
    }

    @Test
    @DisplayName("Should log JWKS_URI_RESOLUTION_FAILED when well-known resolver cannot resolve JWKS URI")
    void shouldLogJwksUriResolutionFailedWhenWellKnownResolverFails(URIBuilder uriBuilder) {
        // Create a well-known config that will fail to resolve JWKS URI
        // Using an invalid well-known endpoint that returns 404
        String invalidWellKnownUrl = uriBuilder.addPathSegment("invalid-well-known").buildAsString();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .wellKnownUrl(invalidWellKnownUrl)
                .build();

        try (HttpJwksLoader failingLoader = new HttpJwksLoader(config)) {
            // Wait for async initialization to complete (even if it fails)
            failingLoader.initJWKSLoader(securityEventCounter).join();

            // Try to get a key, which should fail because JWKS URI cannot be resolved
            Optional<KeyInfo> keyInfo = failingLoader.getKeyInfo(TEST_KID);
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWKS URI resolution fails");

            // Verify JWKS_URI_RESOLUTION_FAILED was logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.JWKS_URI_RESOLUTION_FAILED.resolveIdentifierString());
        }
    }

    @Test
    @DisplayName("Should not support symmetric keys (oct type)")
    void shouldNotSupportSymmetricKeys(URIBuilder uriBuilder) {
        // Save current dispatcher state
        String previousResponse = moduleDispatcher.getCustomResponse();

        try {
            // Setup mock to return symmetric key JWKS
            moduleDispatcher.setCustomResponse("""
                    {
                        "keys": [{
                            "kty": "oct",
                            "use": "sig",
                            "kid": "symmetric-key-1",
                            "k": "GawgguFyGrWKav7AX4VKUg",
                            "alg": "HS256"
                        }]
                    }
                    """);

            String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
            HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                    .jwksUrl(jwksEndpoint)
                    .issuerIdentifier("test-issuer")
                    .build();

            try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
                // Wait for async initialization to complete
                loader.initJWKSLoader(securityEventCounter).join();

                // Try to get the symmetric key - should not be found as oct keys are filtered out
                Optional<KeyInfo> keyInfo = loader.getKeyInfo("symmetric-key-1");
                assertFalse(keyInfo.isPresent(), "Symmetric key should not be supported");

                // The key is simply not found - oct keys are filtered out in JWKSKeyLoader
                // No UNSUPPORTED_JWKS_TYPE error is logged as the filtering happens silently
            }
        } finally {
            // Restore dispatcher state
            moduleDispatcher.setCustomResponse(previousResponse);
        }
    }
}
