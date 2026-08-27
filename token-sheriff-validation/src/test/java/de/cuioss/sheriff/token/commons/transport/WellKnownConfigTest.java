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

import de.cuioss.http.client.handler.SecureSSLContextProvider;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests WellKnownConfig")
class WellKnownConfigTest {

    private static final String TEST_WELL_KNOWN_URL = "https://example.com/.well-known/openid-configuration";
    private static final URI TEST_WELL_KNOWN_URI = URI.create(TEST_WELL_KNOWN_URL);
    private static final String INSECURE_WELL_KNOWN_URL = "http://example.com/.well-known/openid-configuration";

    @Test
    @DisplayName("Should reject insecure HTTP well-known URL by default (cleartext is opt-in)")
    void shouldRejectInsecureHttpWellKnownUrlByDefault() {
        var builder = WellKnownConfig.builder()
                .wellKnownUrl(INSECURE_WELL_KNOWN_URL);
        assertThrows(IllegalArgumentException.class, builder::build,
                "http:// well-known URL must be rejected by default without an explicit opt-in");
    }

    @Test
    @DisplayName("Should warn about insecure HTTP well-known discovery URL under explicit opt-in")
    void shouldWarnAboutInsecureHttpWellKnownUrl() {
        WellKnownConfig config = WellKnownConfig.builder()
                .allowInsecureHttp(true)
                .wellKnownUrl(INSECURE_WELL_KNOWN_URL)
                .build();

        assertTrue(config.getHttpHandler().getUri().toString().startsWith("http://"),
                "Insecure HTTP well-known URL is allowed when insecure HTTP is explicitly enabled");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INSECURE_HTTP_WELLKNOWN.resolveIdentifierString());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, INSECURE_WELL_KNOWN_URL);
    }

    @Test
    @DisplayName("Should reject insecure HTTP well-known URL when allowInsecureHttp(false)")
    void shouldRejectInsecureHttpWellKnownUrlWhenDisallowed() {
        var builder = WellKnownConfig.builder()
                .allowInsecureHttp(false)
                .wellKnownUrl(INSECURE_WELL_KNOWN_URL);
        assertThrows(IllegalArgumentException.class, builder::build,
                "http:// well-known URL must be rejected when insecure HTTP is disallowed");
    }

    @Test
    @DisplayName("Should allow https well-known URL when allowInsecureHttp(false)")
    void shouldAllowHttpsWellKnownUrlWhenInsecureDisallowed() {
        WellKnownConfig config = WellKnownConfig.builder()
                .allowInsecureHttp(false)
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .build();

        assertNotNull(config.getHttpHandler());
        assertTrue(config.getHttpHandler().getUri().toString().startsWith("https://"));
    }

    @Test
    @DisplayName("Should reject a discovery host resolving to a blocked range when no egress opt-in is set")
    void shouldRejectBlockedDiscoveryHostWithoutEgressOptIn() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .build();
        // "localhost" resolves to a loopback address, which the secure-default egress guard blocks.
        assertThrows(TransportException.class,
                () -> config.getEgressPolicy().check(URI.create("https://localhost:8443/.well-known/openid-configuration")),
                "A loopback-resolving discovery host must be blocked when no egress opt-in is configured");
    }

    @Test
    @DisplayName("Should permit a discovery host that is on the explicit egress allow-list")
    void shouldPermitAllowedEgressDiscoveryHost() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .allowedEgressHost("localhost")
                .build();
        assertDoesNotThrow(
                () -> config.getEgressPolicy().check(URI.create("https://localhost:8443/.well-known/openid-configuration")),
                "An allow-listed discovery host must bypass the egress address-range checks");
    }

    @Test
    @DisplayName("Should create config with URL string")
    void shouldCreateConfigWithUrl() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .build();

        assertNotNull(config.getHttpHandler());
        assertEquals(TEST_WELL_KNOWN_URI.toString(), config.getHttpHandler().getUri().toString());
    }

    @Test
    @DisplayName("Should create config with URI")
    void shouldCreateConfigWithUri() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUri(TEST_WELL_KNOWN_URI)
                .build();

        assertNotNull(config.getHttpHandler());
        assertEquals(TEST_WELL_KNOWN_URI, config.getHttpHandler().getUri());
    }

    @Test
    @DisplayName("Should create config with custom timeouts")
    void shouldCreateConfigWithCustomTimeouts() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .connectTimeoutSeconds(5)
                .readTimeoutSeconds(10)
                .build();

        assertNotNull(config.getHttpHandler());
        // HTTP handler should be created with the custom timeouts (can't directly verify timeouts from HttpHandler)
    }

    @Test
    @DisplayName("Should fail when no well-known URI configured")
    void shouldFailWhenNoWellKnownUri() {
        WellKnownConfig.WellKnownConfigBuilder builder = WellKnownConfig.builder();

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertTrue(exception.getMessage().contains("Invalid well-known endpoint configuration"));
    }

    @Test
    @DisplayName("Should use default exponential backoff when RetryConfig not specified")
    void shouldUseDefaultRetryConfig() {
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .build();

        assertNotNull(config.getRetryConfig());
        // Should be exponential backoff strategy by default
        assertNotNull(config.getHttpHandler());
    }

    @Test
    @DisplayName("Should fail with invalid timeout values")
    void shouldFailWithInvalidTimeouts() {
        // Test invalid connect timeout
        var builderWithInvalidConnectTimeout = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .connectTimeoutSeconds(0);

        assertThrows(IllegalArgumentException.class, builderWithInvalidConnectTimeout::build);

        // Test invalid read timeout
        var builderWithInvalidReadTimeout = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .readTimeoutSeconds(-1);

        assertThrows(IllegalArgumentException.class, builderWithInvalidReadTimeout::build);
    }

    @Test
    @DisplayName("Should create config with custom SSL context")
    void shouldCreateConfigWithCustomSslContext() throws Exception {
        // Create a custom SSL context
        SSLContext customSslContext = SSLContext.getDefault();

        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .sslContext(customSslContext)
                .build();

        assertNotNull(config.getHttpHandler());
        // The SSL context is set on the underlying HTTP handler
        // We can't directly verify it but the builder method should work without exceptions
    }

    @Test
    @DisplayName("Should support sslContext() method in builder API")
    void shouldSupportSslContextBuilderMethod() throws Exception {
        // API test: verify sslContext() method exists and returns builder for chaining
        SSLContext sslContext = SSLContext.getDefault();

        WellKnownConfig.WellKnownConfigBuilder builder = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .sslContext(sslContext);

        // Verify the method returns the builder instance for chaining
        assertNotNull(builder);
        assertInstanceOf(WellKnownConfig.WellKnownConfigBuilder.class, builder);

        // Verify the builder can still build successfully
        WellKnownConfig config = builder.build();
        assertNotNull(config);
    }

    @Test
    @DisplayName("Should support tlsVersions() method in builder API")
    void shouldSupportTlsVersionsBuilderMethod() {
        // API test: verify tlsVersions() method exists and returns builder for chaining
        // Using the existing SecureSSLContextProvider with its constants
        SecureSSLContextProvider tlsProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);

        WellKnownConfig.WellKnownConfigBuilder builder = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .tlsVersions(tlsProvider);

        // Verify the method returns the builder instance for chaining
        assertNotNull(builder);
        assertInstanceOf(WellKnownConfig.WellKnownConfigBuilder.class, builder);

        // Verify the builder can still build successfully
        WellKnownConfig config = builder.build();
        assertNotNull(config);
    }

    @Test
    @DisplayName("Should allow chaining of sslContext() and tlsVersions() methods")
    void shouldAllowChainingOfSslContextAndTlsVersionsMethods() throws Exception {
        // API test: verify both methods can be chained together
        SSLContext sslContext = SSLContext.getDefault();
        SecureSSLContextProvider tlsProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_2);

        // Test method chaining
        WellKnownConfig config = WellKnownConfig.builder()
                .wellKnownUrl(TEST_WELL_KNOWN_URL)
                .sslContext(sslContext)           // First method
                .tlsVersions(tlsProvider)         // Second method
                .connectTimeoutSeconds(10)        // Other methods still work
                .readTimeoutSeconds(20)
                .build();

        assertNotNull(config);
        assertNotNull(config.getHttpHandler());
    }
}
