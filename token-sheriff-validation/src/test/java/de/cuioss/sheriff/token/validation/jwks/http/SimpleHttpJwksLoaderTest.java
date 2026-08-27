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
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableMockWebServer
class SimpleHttpJwksLoaderTest {

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private HttpJwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        httpJwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        httpJwksLoader.initJWKSLoader(securityEventCounter).join();
    }

    @Test
    void basicKeyLoading() {
        // With async initialization, loading happens during initJWKSLoader
        // Since we wait for it to complete in setUp, status should be OK
        assertEquals(LoaderStatus.OK, httpJwksLoader.getLoaderStatus());

        // Get a key - loading already happened during initialization
        httpJwksLoader.getKeyInfo("test-key-id");

        // Status should still be OK
        assertEquals(LoaderStatus.OK, httpJwksLoader.getLoaderStatus());

        // Should have called endpoint once during initialization
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Load a key - should use already loaded keys
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        assertTrue(keyInfo.isPresent());
        assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, keyInfo.get().keyId());

        // Should still have called endpoint only once (cached)
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void caching() {
        // Multiple calls should only hit endpoint once
        httpJwksLoader.getKeyInfo(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        httpJwksLoader.getKeyInfo(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        httpJwksLoader.getKeyInfo("another-key-id");
        httpJwksLoader.getLoaderStatus();

        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void retryOnLoad() {
        // The RetryUtil should handle transient failures automatically
        // This test verifies basic functionality works
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);
        assertTrue(keyInfo.isPresent());
        assertNotNull(keyInfo.get().key());
    }
}
