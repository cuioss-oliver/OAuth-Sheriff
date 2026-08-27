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
package de.cuioss.sheriff.token.validation.jwks;

import de.cuioss.http.client.adapter.RetryConfig;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.JwksType;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.jwks.http.HttpJwksLoader;
import de.cuioss.sheriff.token.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwksLoaderFactory} that verify different JWKS loading strategies.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4.1">VALIDATION-4.1: JWKS Endpoint Support</a> (HTTP loading)</li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4.4">VALIDATION-4.4: Local Key Support</a> (file and in-memory loading)</li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.3">VALIDATION-7.3: Security Events</a> (JWKS operation tracking)</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#jwks-integration">JWKS Integration Specification</a>
 */
@EnableTestLogger
@DisplayName("Tests for JwksLoaderFactory")
class JwksLoaderFactoryTest {

    private SecurityEventCounter securityEventCounter;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();
    }

    @Test
    @DisplayName("Should create HTTP loader")
    void shouldCreateHttpLoader() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl("https://example.com/.well-known/jwks.json")
                .issuerIdentifier("test-issuer")
                .retryConfig(RetryConfig.builder().maxAttempts(1).build()) // No retry to avoid delays - HTTP functionality tested in ResilientHttpAdapter
                .build();
        JwksLoader loader = JwksLoaderFactory.createHttpLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(HttpJwksLoader.class, loader, "Loader should be an instance of HttpJwksLoader");
        assertEquals(JwksType.HTTP, loader.getJwksType(), "Loader should have HTTP type");
        // Trigger loading by attempting to get a key, then check health status
        loader.getKeyInfo("test-key-id"); // This triggers loading attempt
        // With retry capability, failed loads no longer set permanent ERROR status
        assertNotEquals(LoaderStatus.ERROR, loader.getLoaderStatus(), "HTTP loader should not have permanent ERROR status (enables retry)");
    }

    @Test
    @DisplayName("Should create well-known discovery loader")
    void shouldCreateWellKnownLoader() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnownUrl("https://example.com/.well-known/openid-configuration")
                .retryConfig(RetryConfig.builder().maxAttempts(1).build()) // No retry to avoid delays - HTTP functionality tested in ResilientHttpAdapter
                .build();
        JwksLoader loader = JwksLoaderFactory.createHttpLoader(config);
        loader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(HttpJwksLoader.class, loader, "Loader should be an instance of HttpJwksLoader");
        assertEquals(JwksType.WELL_KNOWN, loader.getJwksType(), "Loader should have WELL_KNOWN type");
        // Trigger loading by attempting to get a key, then check health status
        loader.getKeyInfo("test-key-id"); // This triggers loading attempt
        // Without background refresh enabled (no refresh interval), failed loads set ERROR status
        assertEquals(LoaderStatus.ERROR, loader.getLoaderStatus(), "Well-known loader should have ERROR status without background refresh");
    }

    @Test
    @DisplayName("Should create file loader")
    void shouldCreateFileLoader(@TempDir Path tempDir) throws Exception {

        Path jwksFile = tempDir.resolve("jwks.json");
        Files.writeString(jwksFile, jwksContent);
        JwksLoader loader = JwksLoaderFactory.createFileLoader(jwksFile.toString());
        loader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
        assertEquals(JwksType.FILE, loader.getJwksType(), "Loader should have FILE type");
        assertEquals(LoaderStatus.OK, loader.getLoaderStatus(), "Loader should have OK status for valid file");
    }

    @Test
    @DisplayName("Should fail fast when creating file loader for non-existent file")
    void shouldFailFastForNonExistentFile() {

        String nonExistentFile = "non-existent-file.json";
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> JwksLoaderFactory.createFileLoader(nonExistentFile),
                "Should throw IllegalArgumentException for non-existent file");

        assertTrue(exception.getMessage().contains("Cannot read JWKS file"),
                "Exception message should indicate file read failure");
        assertTrue(exception.getMessage().contains(nonExistentFile),
                "Exception message should contain the file name");
    }

    @Test
    @DisplayName("Should create in-memory loader")
    void shouldCreateInMemoryLoader() {

        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        loader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
        assertEquals(JwksType.MEMORY, loader.getJwksType(), "Loader should have MEMORY type");
        assertEquals(LoaderStatus.OK, loader.getLoaderStatus(), "Loader should have OK status for valid content");
    }

    @Test
    @DisplayName("Should create in-memory loader with fallback for invalid content")
    void shouldCreateInMemoryLoaderWithFallbackForInvalidContent() {

        String invalidContent = "invalid-json";
        JwksLoader loader = JwksLoaderFactory.createInMemoryLoader(invalidContent);
        loader.initJWKSLoader(securityEventCounter).join();
        assertNotNull(loader, "Loader should not be null");
        assertInstanceOf(JWKSKeyLoader.class, loader, "Loader should be an instance of JWKSKeyLoader");
        assertEquals(JwksType.MEMORY, loader.getJwksType(), "Loader should have MEMORY type");
        assertEquals(LoaderStatus.ERROR, loader.getLoaderStatus(), "Loader should have ERROR status for invalid content");

        // The JWKSKeyLoader constructor now automatically increments the counter when it encounters invalid JSON content

        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "Should count JWKS_JSON_PARSE_FAILED event");
    }

}
