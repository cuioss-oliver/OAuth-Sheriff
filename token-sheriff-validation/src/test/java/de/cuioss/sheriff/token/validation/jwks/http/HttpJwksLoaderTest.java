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
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcher;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("HttpJwksLoader Core Functionality Tests")
@EnableMockWebServer
class HttpJwksLoaderTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private HttpJwksLoader httpJwksLoader;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        httpJwksLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        httpJwksLoader.initJWKSLoader(securityEventCounter).join();
    }

    @Test
    @DisplayName("Should create loader with constructor")
    void shouldCreateLoaderWithConstructor() {
        assertNotNull(httpJwksLoader, "HttpJwksLoader should not be null");
        assertNotNull(httpJwksLoader.getLoaderStatus(), "Status should be available");
    }

    @Test
    @DisplayName("Should get key info by ID")
    void shouldGetKeyInfoById() {
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(TEST_KID, keyInfo.get().keyId(), "Key ID should match");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called once");
    }

    @Test
    @DisplayName("Should return empty for unknown key ID")
    void shouldReturnEmptyForUnknownKeyId() {
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo("unknown-kid");
        assertFalse(keyInfo.isPresent(), "Key info should not be present for unknown key ID");
    }

    @Test
    @DisplayName("Should return empty for null key ID")
    void shouldReturnEmptyForNullKeyId() {
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(null);
        assertFalse(keyInfo.isPresent(), "Key info should not be present for null key ID");
    }

    @Test
    @DisplayName("Should get key info for test kid")
    void shouldGetKeyInfoForTestKid() {
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present for test kid");
        assertEquals(TEST_KID, keyInfo.get().keyId(), "Key ID should match test kid");
    }

    @Test
    @DisplayName("Should verify key loading works")
    void shouldVerifyKeyLoadingWorks() {
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertNotNull(keyInfo.get().key(), "Public key should not be null");
    }

    @Test
    @DisplayName("Should verify test key exists")
    void shouldVerifyTestKeyExists() {
        assertTrue(httpJwksLoader.getKeyInfo(TEST_KID).isPresent(),
                "Test key with ID '" + TEST_KID + "' should exist");
    }

    @Test
    @DisplayName("Should load keys on first access and cache in memory")
    void shouldLoadKeysOnFirstAccess() {
        // First call should load
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called once");

        // Subsequent calls should use the already loaded keys without additional HTTP calls
        keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should still be present");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should still be called only once");
    }

    @Test
    @DisplayName("Should handle health checks")
    void shouldHandleHealthChecks() {
        // Initially undefined status
        assertNotNull(httpJwksLoader.getLoaderStatus(), "Status should not be null");

        // After loading, should be healthy
        httpJwksLoader.getKeyInfo(TEST_KID);
        assertEquals(LoaderStatus.OK, httpJwksLoader.getLoaderStatus(), "Should be healthy after successful load");
    }

    @Test
    @ModuleDispatcher
    @DisplayName("Should create new loader with simplified config")
    void shouldCreateNewLoaderWithSimplifiedConfig(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();

        HttpJwksLoader customLoader = new HttpJwksLoader(config);
        // Wait for async initialization to complete
        customLoader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(customLoader);

        // Verify it works
        Optional<KeyInfo> keyInfo = customLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
    }

    @Test
    @DisplayName("Should work with multiple loader instances")
    void shouldWorkWithMultipleLoaderInstances(URIBuilder uriBuilder) {
        // First, get a key to ensure keys are loaded
        Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

        // Create a new loader instance with the same configuration
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .build();
        try (HttpJwksLoader newLoader = new HttpJwksLoader(config)) {
            // Wait for async initialization to complete
            newLoader.initJWKSLoader(securityEventCounter).join();

            // Verify the new loader works independently
            assertNotNull(newLoader.getLoaderStatus(), "Health check should work for new loader");

            // Both loaders should be functional
            Optional<KeyInfo> originalLoaderKey = httpJwksLoader.getKeyInfo(TEST_KID);
            Optional<KeyInfo> newLoaderKey = newLoader.getKeyInfo(TEST_KID);
            assertTrue(originalLoaderKey.isPresent(), "Original loader should have the key");
            assertTrue(newLoaderKey.isPresent(), "New loader should be able to retrieve the key");
        }
    }

    @Test
    @DisplayName("Should log info message when JWKS is loaded and parsed")
    void shouldLogInfoMessageWhenJwksIsLoadedAndParsed() {
        // When loading a key, the JWKS is loaded and parsed
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

        // Then the key should be found
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Verify that JWKS loaded message is logged with issuer information
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                "JWKS loaded successfully for issuer");
    }

    @Test
    @DisplayName("Should log JWKS_LOADED when JWKS is loaded via HTTP")
    void shouldLogJwksLoadedWhenJwksIsLoadedViaHttp() {
        // First access loads keys via HTTP
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Verify JWKS_LOADED was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO,
                JWTValidationLogMessages.INFO.JWKS_LOADED.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should log JWKS_KEYS_UPDATED when keys are updated")
    void shouldLogJwksKeysUpdatedWhenKeysAreUpdated() {
        // Load a key to trigger keys update
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // JWKS_KEYS_UPDATED is logged when keys are successfully loaded and updated
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO,
                JWTValidationLogMessages.INFO.JWKS_KEYS_UPDATED.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should load JWKS successfully with custom ParserConfig")
    void shouldLoadJwksWithCustomParserConfig(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Create a custom ParserConfig (pre-initialized on caller's thread)
        ParserConfig customParserConfig = ParserConfig.builder().build();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowLoopbackEgress(true).allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .parserConfig(customParserConfig)
                .build();

        try (HttpJwksLoader loader = new HttpJwksLoader(config)) {
            loader.initJWKSLoader(securityEventCounter).join();

            assertEquals(LoaderStatus.OK, loader.getLoaderStatus(),
                    "Loader should be OK with custom ParserConfig");
            Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(),
                    "Key info should be present with custom ParserConfig");
        }
    }
}
