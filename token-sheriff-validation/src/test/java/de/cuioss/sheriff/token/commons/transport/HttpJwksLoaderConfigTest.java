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
import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.http.client.handler.SecureSSLContextProvider;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests HttpJwksLoaderConfig")
@SuppressWarnings("java:S5778")
// owolff: Suppressing because for a builder this is not a problem
class HttpJwksLoaderConfigTest {

    private static final String VALID_URL = "https://example.com/.well-known/jwks.json";
    private static final String WELL_KNOWN_URL = "https://example.com/.well-known/openid-configuration";
    private static final int REFRESH_INTERVAL = 60;

    @Test
    @DisplayName("Should reject http:// JWKS URL when allowInsecureHttp(false)")
    void shouldRejectInsecureHttpWhenDisallowed() {
        var builder = HttpJwksLoaderConfig.builder()
                .jwksUrl("http://example.com/.well-known/jwks.json")
                .issuerIdentifier("test-issuer")
                .allowInsecureHttp(false);
        assertThrows(IllegalArgumentException.class, builder::build,
                "http:// JWKS URL must be rejected when insecure HTTP is disallowed");
    }

    @Test
    @DisplayName("Should allow https:// JWKS URL when allowInsecureHttp(false)")
    void shouldAllowHttpsWhenInsecureDisallowed() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .allowInsecureHttp(false)
                .build();
        assertTrue(config.getHttpHandler().getUrl().toString().startsWith("https://"),
                "https:// JWKS URL must be accepted when insecure HTTP is disallowed");
    }

    @Test
    @DisplayName("Should reject http:// JWKS URL by default (cleartext is opt-in)")
    void shouldRejectInsecureHttpByDefault() {
        var builder = HttpJwksLoaderConfig.builder()
                .jwksUrl("http://example.com/.well-known/jwks.json")
                .issuerIdentifier("test-issuer");
        assertThrows(IllegalArgumentException.class, builder::build,
                "http:// JWKS URL must be rejected by default without an explicit opt-in");
    }

    @Test
    @DisplayName("Should allow http:// JWKS URL only when allowInsecureHttp(true) is set explicitly")
    void shouldAllowInsecureHttpWhenExplicitlyEnabled() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl("http://example.com/.well-known/jwks.json")
                .issuerIdentifier("test-issuer")
                .allowInsecureHttp(true)
                .build();
        assertTrue(config.getHttpHandler().getUri().toString().startsWith("http://"),
                "http:// JWKS URL must be accepted when insecure HTTP is explicitly enabled");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INSECURE_HTTP_JWKS.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should warn when creating a handler for a discovered http:// JWKS URL under explicit opt-in")
    void shouldWarnForDiscoveredInsecureJwksUrl() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .allowInsecureHttp(true)
                .build();

        HttpHandler handler = config.getHttpHandler("http://internal.example/jwks.json");
        assertTrue(handler.getUri().toString().startsWith("http://"),
                "Discovered http:// JWKS URL is allowed when insecure HTTP is explicitly enabled");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INSECURE_HTTP_JWKS.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should reject a JWKS host resolving to a blocked range when no egress opt-in is set")
    void shouldRejectBlockedHostWithoutEgressOptIn() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .build();
        // "localhost" resolves to a loopback address, which the secure-default egress guard blocks.
        assertThrows(TransportException.class,
                () -> config.getEgressPolicy().check(URI.create("https://localhost:8443/certs")),
                "A loopback-resolving host must be blocked when no egress opt-in is configured");
    }

    @Test
    @DisplayName("Should permit a JWKS host that is on the explicit egress allow-list")
    void shouldPermitAllowedEgressHost() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .allowedEgressHost("localhost")
                .build();
        // The allow-list bypasses the address-range checks entirely, so the otherwise-blocked
        // loopback resolution of "localhost" is permitted.
        assertDoesNotThrow(
                () -> config.getEgressPolicy().check(URI.create("https://localhost:8443/certs")),
                "An allow-listed host must bypass the egress address-range checks");
    }

    @Test
    @DisplayName("Should create config with default values")
    void shouldCreateConfigWithDefaultValues() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();
        assertEquals(URI.create(VALID_URL), config.getHttpHandler().getUri());
        assertEquals(REFRESH_INTERVAL, config.getRefreshIntervalSeconds());
        assertNotNull(config.getHttpHandler().getSslContext());
        assertNotNull(config.getScheduledExecutorService(), "Default executor service should be created");
    }

    @Test
    @DisplayName("Should create config with custom values")
    void shouldCreateConfigWithCustomValues() throws Exception {

        SSLContext sslContext = SSLContext.getDefault();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .sslContext(sslContext)
                .build();
        assertEquals(URI.create(VALID_URL), config.getHttpHandler().getUri());
        assertEquals(REFRESH_INTERVAL, config.getRefreshIntervalSeconds());
        assertNotNull(config.getHttpHandler().getSslContext());
    }

    @Test
    @DisplayName("Should handle URL without scheme")
    void shouldHandleUrlWithoutScheme() {

        String urlWithoutScheme = "example.com/jwks.json";
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(urlWithoutScheme)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();
        assertEquals(URI.create("https://" + urlWithoutScheme), config.getHttpHandler().getUri());
    }

    @Test
    @DisplayName("Should use SecureSSLContextProvider")
    void shouldUseSecureSSLContextProvider() {

        SecureSSLContextProvider secureProvider = new SecureSSLContextProvider();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .tlsVersions(secureProvider)
                .build();
        assertNotNull(config.getHttpHandler().getSslContext());
    }

    @Test
    @DisplayName("Should throw exception for negative refresh interval")
    void shouldThrowExceptionForNegativeRefreshInterval() {

        int negativeRefreshInterval = -1;
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(negativeRefreshInterval)
                .build());
    }


    @Test
    @DisplayName("Should throw exception for missing JWKS URL")
    void shouldThrowExceptionForMissingJwksUrl() {

        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build());
    }

    @Test
    @DisplayName("Should use custom ScheduledExecutorService")
    void shouldUseCustomScheduledExecutorService() {

        ScheduledExecutorService customExecutorService = Executors.newScheduledThreadPool(2);
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .scheduledExecutorService(customExecutorService)
                .build();
        assertSame(customExecutorService, config.getScheduledExecutorService(),
                "Custom executor service should be used");

        // Clean up
        customExecutorService.shutdown();
    }

    @Test
    @DisplayName("Should create default ScheduledExecutorService when refresh interval is positive")
    void shouldCreateDefaultScheduledExecutorServiceWhenRefreshIntervalPositive() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL) // Positive refresh interval
                .build();
        assertNotNull(config.getScheduledExecutorService(),
                "Default executor service should be created for positive refresh interval");
    }

    @Test
    @DisplayName("Should not create ScheduledExecutorService when refresh interval is zero")
    void shouldNotCreateScheduledExecutorServiceWhenRefreshIntervalZero() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(0) // Zero refresh interval
                .build();
        assertNull(config.getScheduledExecutorService(),
                "No executor service should be created for zero refresh interval");
    }


    @Test
    @DisplayName("Should handle URI parameter method")
    void shouldHandleUriParameter() {

        URI testUri = URI.create(VALID_URL);
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUri(testUri)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();
        assertEquals(testUri, config.getHttpHandler().getUri(),
                "URI should be set correctly");
    }

    @Test
    @DisplayName("Should apply explicit JWKS transport timeout defaults consistent with discovery (M8)")
    void shouldApplyExplicitTransportTimeoutDefaults() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        HttpHandler handler = config.getHttpHandler();
        assertAll("Explicit JWKS transport timeout defaults (M8)",
                () -> assertEquals(2, handler.getConnectionTimeoutSeconds(),
                        "Default JWKS connect timeout must be 2s to match the discovery transport, not cui-http's laxer 10s default"),
                () -> assertEquals(3, handler.getReadTimeoutSeconds(),
                        "Default JWKS read timeout must be 3s to match the discovery transport, not cui-http's laxer 10s default"));
    }

    @Test
    @DisplayName("Should set connect timeout seconds")
    void shouldSetConnectTimeoutSeconds() {

        int connectTimeout = 30;
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .connectTimeoutSeconds(connectTimeout)
                .build();
        assertEquals(connectTimeout, config.getHttpHandler().getConnectionTimeoutSeconds(),
                "Explicit connect timeout must override the default and be carried by the HttpHandler");
    }

    @Test
    @DisplayName("Should set read timeout seconds")
    void shouldSetReadTimeoutSeconds() {

        int readTimeout = 60;
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .readTimeoutSeconds(readTimeout)
                .build();
        assertEquals(readTimeout, config.getHttpHandler().getReadTimeoutSeconds(),
                "Explicit read timeout must override the default and be carried by the HttpHandler");
    }

    @Test
    @DisplayName("Should set both connect and read timeout seconds")
    void shouldSetBothTimeouts() {

        int connectTimeout = 30;
        int readTimeout = 60;
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .connectTimeoutSeconds(connectTimeout)
                .readTimeoutSeconds(readTimeout)
                .build();
        HttpHandler handler = config.getHttpHandler();
        assertAll("Explicit connect and read timeouts",
                () -> assertEquals(connectTimeout, handler.getConnectionTimeoutSeconds(),
                        "Explicit connect timeout must be carried by the HttpHandler"),
                () -> assertEquals(readTimeout, handler.getReadTimeoutSeconds(),
                        "Explicit read timeout must be carried by the HttpHandler"));
    }

    @Test
    @DisplayName("Should throw exception for zero connect timeout seconds")
    void shouldThrowExceptionForZeroConnectTimeoutSeconds() {

        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .connectTimeoutSeconds(0)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative connect timeout seconds")
    void shouldThrowExceptionForNegativeConnectTimeoutSeconds() {

        int negativeConnectTimeout = -1;
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .connectTimeoutSeconds(negativeConnectTimeout)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for zero read timeout seconds")
    void shouldThrowExceptionForZeroReadTimeoutSeconds() {

        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .readTimeoutSeconds(0)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative read timeout seconds")
    void shouldThrowExceptionForNegativeReadTimeoutSeconds() {

        int negativeReadTimeout = -1;
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .readTimeoutSeconds(negativeReadTimeout)
                .build());
    }

    @Test
    @DisplayName("Should test toString method")
    void shouldTestToStringMethod() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();
        String toString = config.toString();
        assertNotNull(toString, "toString should not return null");
        assertFalse(toString.isEmpty(), "toString should not be empty");
        assertTrue(toString.contains("HttpJwksLoaderConfig"), "toString should contain class name");
    }

    @Test
    @DisplayName("Should test equals and hashCode methods")
    void shouldTestEqualsAndHashCode() {
        // Use same RetryConfig instance for both configs since it's now part of equals/hashCode
        RetryConfig sharedRetryConfig = RetryConfig.defaults();

        HttpJwksLoaderConfig config1 = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .retryConfig(sharedRetryConfig)
                .build();

        HttpJwksLoaderConfig config2 = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .retryConfig(sharedRetryConfig)
                .build();

        HttpJwksLoaderConfig config3 = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(120) // Different value
                .retryConfig(sharedRetryConfig)
                .build();
        assertEquals(config1, config2, "Configs with same values should be equal");
        assertEquals(config1.hashCode(), config2.hashCode(), "Configs with same values should have same hashCode");
        assertNotEquals(config1, config3, "Configs with different values should not be equal");
        assertNotNull(config1, "Config should not equal null");
    }

    @Test
    @DisplayName("Should throw exception when no endpoint configuration is provided")
    void shouldThrowExceptionWhenNoEndpointConfigured() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                HttpJwksLoaderConfig.builder()
                        .refreshIntervalSeconds(REFRESH_INTERVAL)
                        .build());

        assertTrue(exception.getMessage().contains("No JWKS endpoint configured"));
        assertTrue(exception.getMessage().contains("Must call one of: jwksUri(), jwksUrl(), wellKnownUrl(), or wellKnownUri()"));
    }

    @Test
    @DisplayName("Should throw exception when jwksUri() and jwksUrl() are both used")
    void shouldThrowExceptionWhenJwksUriAndJwksUrlBothUsed() {
        HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder builder = HttpJwksLoaderConfig.builder()
                .jwksUri(URI.create(VALID_URL));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                builder.jwksUrl("https://another.example.com/jwks.json"));

        String message = exception.getMessage();
        assertTrue(message.contains("Cannot use jwksurl endpoint configuration when jwksuri was already configured"),
                "Expected message to contain exclusivity info, but was: " + message);
        assertTrue(message.contains("mutually exclusive"),
                "Expected message to contain 'mutually exclusive', but was: " + message);
    }

    @Test
    @DisplayName("Should throw exception when jwksUrl() and jwksUri() are both used")
    void shouldThrowExceptionWhenJwksUrlAndJwksUriBothUsed() {
        HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder builder = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                builder.jwksUri(URI.create("https://another.example.com/jwks.json")));

        String message = exception.getMessage();
        assertTrue(message.contains("Cannot use jwksuri endpoint configuration when jwksurl was already configured"),
                "Expected message to contain exclusivity info, but was: " + message);
        assertTrue(message.contains("mutually exclusive"),
                "Expected message to contain 'mutually exclusive', but was: " + message);
    }

    @Test
    @DisplayName("Should allow multiple calls to same endpoint configuration method")
    void shouldAllowMultipleCallsToSameEndpointMethod() {
        // This should not throw an exception - multiple calls to the same method should be allowed
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .jwksUrl("https://final.example.com/jwks.json") // Override with different URL
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        assertEquals(URI.create("https://final.example.com/jwks.json"), config.getHttpHandler().getUri());
    }

    @Test
    @DisplayName("Should throw exception for invalid URL that causes HttpHandler build failure")
    void shouldThrowExceptionForInvalidUrlCausingHttpHandlerFailure() {
        // Test with a malformed URL that would cause HttpHandler.build() to fail
        assertThrows(IllegalArgumentException.class, () ->
                HttpJwksLoaderConfig.builder()
                        .jwksUrl("not-a-valid-url://invalid")
                        .issuerIdentifier("test-issuer")
                        .refreshIntervalSeconds(REFRESH_INTERVAL)
                        .build());

        // Verify the warning was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_JWKS_URI.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should guarantee HttpHandler is non-null for HTTP configurations")
    void shouldGuaranteeHttpHandlerNonNullForHttpConfigurations() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Verify the contract: HttpHandler is guaranteed non-null for HTTP configurations
        assertNotNull(config.getHttpHandler(), "HttpHandler must be non-null for HTTP configurations");
        assertNull(config.getWellKnownConfig(), "WellKnownConfig should be null for HTTP configurations");
    }

    @Test
    @DisplayName("Should guarantee WellKnownConfig is non-null for well-known configurations")
    void shouldGuaranteeWellKnownConfigNonNullForWellKnownConfigurations() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnownUrl("https://example.com/.well-known/openid-configuration")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Verify the contract: WellKnownConfig is guaranteed non-null for well-known configurations
        assertNotNull(config.getWellKnownConfig(), "WellKnownConfig must be non-null for well-known configurations");
        // HttpJwksLoaderConfig now implements HttpHandlerProvider, so getHttpHandler() returns the HttpHandler from WellKnownConfig
        assertNotNull(config.getHttpHandler(), "HttpHandler should be accessible via HttpHandlerProvider interface in well-known mode");
    }

    @Test
    @DisplayName("Should use custom ParserConfig when provided")
    void shouldUseCustomParserConfig() {
        ParserConfig customParserConfig = ParserConfig.builder().build();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .parserConfig(customParserConfig)
                .build();

        assertSame(customParserConfig, config.getParserConfig(),
                "Custom ParserConfig should be used");
    }

    @Test
    @DisplayName("Should create default ParserConfig when not provided")
    void shouldCreateDefaultParserConfigWhenNotProvided() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .build();

        assertNotNull(config.getParserConfig(),
                "Default ParserConfig should be created when not provided");
    }

    @Test
    @DisplayName("Should use custom ParserConfig in well-known configuration")
    void shouldUseCustomParserConfigInWellKnownConfig() {
        ParserConfig customParserConfig = ParserConfig.builder().build();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnownUrl("https://example.com/.well-known/openid-configuration")
                .parserConfig(customParserConfig)
                .build();

        assertSame(customParserConfig, config.getParserConfig(),
                "Custom ParserConfig should be used in well-known config");
        assertNotNull(config.getWellKnownConfig(),
                "WellKnownConfig should be created with the custom ParserConfig");
    }

    @Test
    @DisplayName("Should enable hostname verification by default on the direct-JWKS branch")
    void shouldEnableHostnameVerificationByDefaultOnDirectBranch() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .build();

        assertTrue(config.getHttpHandler().isVerifyHostname(),
                "hostname verification must stay enabled when the knob is never called");
    }

    @Test
    @DisplayName("Should enable hostname verification by default on the well-known branch")
    void shouldEnableHostnameVerificationByDefaultOnWellKnownBranch() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnownUrl(WELL_KNOWN_URL)
                .build();

        assertTrue(config.getHttpHandler().isVerifyHostname(),
                "the discovery transport must default to hostname verification enabled");
    }

    @Test
    @DisplayName("Should forward verifyHostname(false) to the handler on the direct-JWKS branch")
    void shouldForwardExplicitVerifyHostnameOnDirectBranch() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .verifyHostname(false)
                .build();

        assertFalse(config.getHttpHandler().isVerifyHostname(),
                "an explicit verifyHostname(false) must reach the built JWKS handler");
    }

    @Test
    @DisplayName("Should forward verifyHostname(false) to the handler on the well-known branch")
    void shouldForwardExplicitVerifyHostnameOnWellKnownBranch() {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .wellKnownUrl(WELL_KNOWN_URL)
                .verifyHostname(false)
                .build();

        assertFalse(config.getHttpHandler().isVerifyHostname(),
                "the knob must not be inert for well-known-configured issuers");
    }

    @Test
    @DisplayName("Should reject verifyHostname(false) combined with sslContext(...) naming the conflict")
    void shouldRejectVerifyHostnameFalseWithSslContext() throws Exception {
        var builder = HttpJwksLoaderConfig.builder()
                .jwksUrl(VALID_URL)
                .issuerIdentifier("test-issuer")
                .verifyHostname(false)
                .sslContext(SSLContext.getDefault());

        var exception = assertThrows(IllegalArgumentException.class, builder::build,
                "the incompatible trust-material combination must be rejected at build()");

        assertTrue(exception.getMessage().contains("verifyHostname(false) cannot be combined with sslContext(...)"),
                "the guard's own message must name the conflict, but was: " + exception.getMessage());
        assertFalse(exception.getMessage().contains("Invalid URL or HttpHandler configuration"),
                "a trust-material conflict must not be reported as a malformed-URL problem");
        assertNull(exception.getCause(),
                "the conflict must be raised first-class, not rewrapped around a nested cause");
    }
}
