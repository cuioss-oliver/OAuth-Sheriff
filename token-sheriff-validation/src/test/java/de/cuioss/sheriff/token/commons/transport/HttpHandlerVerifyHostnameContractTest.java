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

import de.cuioss.http.client.handler.HttpHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Characterization test pinning the four upstream {@code cui-http} properties this project's
 * hostname-verification wiring builds on.
 * <p>
 * This class deliberately tests a dependency rather than local code. Each assertion corresponds to a
 * behaviour that {@link HttpJwksLoaderConfig} and the client back-channel rely on; if a future
 * {@code cui-http} upgrade changes any of them, it breaks here with a named assertion instead of
 * surfacing downstream as a diffuse TLS handshake failure across two modules.
 * <p>
 * The class also serves as the capability-level proof of the dependency floor: it only compiles
 * against a {@code cui-http} that exposes {@code HttpHandlerBuilder.verifyHostname(boolean)}, which
 * is a proof no build-level version rule can give — a version string names a coordinate, not the API
 * the artifact behind it actually carries.
 *
 * @since 1.0
 */
@DisplayName("Tests the upstream cui-http verifyHostname contract")
@SuppressWarnings("java:S5778")
// owolff: Suppressing because for a builder this is not a problem
class HttpHandlerVerifyHostnameContractTest {

    private static final String BASE_URL = "https://example.com/.well-known/jwks.json";
    private static final String OTHER_URL = "https://other.example.com/keys/jwks.json";

    @Test
    @DisplayName("Should enable hostname verification by default (the knob is an opt-out)")
    void shouldEnableHostnameVerificationByDefault() {
        // Arrange & Act — no explicit verifyHostname() call
        HttpHandler handler = HttpHandler.builder()
                .url(BASE_URL)
                .build();

        // Assert
        assertTrue(handler.isVerifyHostname(),
                "upstream default must be verification-enabled, so this project's default-ON claim needs no local defaulting code");
    }

    @ParameterizedTest(name = "verifyHostname({0}) survives the asBuilder() round-trip")
    @ValueSource(booleans = {true, false})
    @DisplayName("Should preserve verifyHostname across the asBuilder() URL round-trip")
    void shouldPreserveVerifyHostnameAcrossAsBuilderRoundTrip(boolean verifyHostname) {
        // Arrange — built without a caller-supplied sslContext, which is the shape
        // HttpJwksLoaderConfig.getHttpHandler(String) actually produces
        HttpHandler baseHandler = HttpHandler.builder()
                .url(BASE_URL)
                .verifyHostname(verifyHostname)
                .build();

        // Act — the round-trip HttpJwksLoaderConfig.getHttpHandler(String) depends on
        HttpHandler rebuilt = baseHandler.asBuilder()
                .url(OTHER_URL)
                .build();

        // Assert
        assertEquals(verifyHostname, rebuilt.isVerifyHostname(),
                "asBuilder() must carry verifyHostname over, otherwise every well-known-discovered JWKS URL silently reverts to the upstream default");
        assertEquals(OTHER_URL, rebuilt.getUri().toString(),
                "the round-trip must still apply the new URL");
    }

    @Test
    @DisplayName("Should reject verifyHostname(false) combined with a caller-supplied sslContext")
    void shouldRejectVerifyHostnameFalseWithCallerSuppliedSslContext() throws Exception {
        // Arrange
        SSLContext callerSupplied = SSLContext.getDefault();
        var builder = HttpHandler.builder()
                .url(BASE_URL)
                .verifyHostname(false)
                .sslContext(callerSupplied);

        // Act
        var exception = assertThrows(IllegalArgumentException.class, builder::build,
                "verifyHostname(false) must not be combinable with a caller-supplied sslContext(...)");

        // Assert — the message must name the conflict, not fail anonymously
        assertTrue(exception.getMessage().contains("verifyHostname(false) cannot be combined with a caller-supplied sslContext(...)"),
                "the guard message must name the conflicting pair, but was: " + exception.getMessage());
    }

    @Test
    @DisplayName("Should leave sibling transport settings untouched when verifyHostname(false) is set")
    void shouldNotDisturbSiblingTransportSettings() {
        // Arrange & Act
        HttpHandler handler = HttpHandler.builder()
                .url(BASE_URL)
                .verifyHostname(false)
                .allowInsecureHttp(true)
                .connectionTimeoutSeconds(7)
                .readTimeoutSeconds(11)
                .build();

        // Assert — the knob is orthogonal, not a broad transport relaxation
        assertFalse(handler.isVerifyHostname(), "explicit verifyHostname(false) must reach the built handler");
        assertTrue(handler.isAllowInsecureHttp(), "allowInsecureHttp must be independent of verifyHostname");
        assertEquals(7, handler.getConnectionTimeoutSeconds(), "connection timeout must be independent of verifyHostname");
        assertEquals(11, handler.getReadTimeoutSeconds(), "read timeout must be independent of verifyHostname");
    }
}
