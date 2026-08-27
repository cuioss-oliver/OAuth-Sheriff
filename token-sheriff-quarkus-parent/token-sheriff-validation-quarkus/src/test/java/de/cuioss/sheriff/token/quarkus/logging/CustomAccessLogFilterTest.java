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
package de.cuioss.sheriff.token.quarkus.logging;

import de.cuioss.sheriff.token.quarkus.config.AccessLogFilterConfigResolver;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.SocketAddress;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.UriInfo;
import org.easymock.EasyMock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests CustomAccessLogFilter functionality.
 * This test focuses on configuration resolution and basic filter behavior.
 */
@EnableTestLogger
class CustomAccessLogFilterTest {

    @Test
    @DisplayName("Should initialize filter with default configuration")
    void shouldInitializeFilterWithDefaultConfig() {
        TestConfig config = new TestConfig(Map.of());
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        assertDoesNotThrow(() -> new CustomAccessLogFilter(resolver, null));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "CustomAccessLogFilter initialized");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "statusCodes=400-599");
    }

    @Test
    @DisplayName("Should initialize filter with custom configuration")
    void shouldInitializeFilterWithCustomConfig() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.MIN_STATUS_CODE, "500",
                JwtPropertyKeys.ACCESSLOG.MAX_STATUS_CODE, "599",
                JwtPropertyKeys.ACCESSLOG.EXCLUDE_PATHS, "/health/**,/metrics/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        assertDoesNotThrow(() -> new CustomAccessLogFilter(resolver, null));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "CustomAccessLogFilter initialized");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "statusCodes=500-599");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/health/**");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/metrics/**");
    }

    @Test
    @DisplayName("Should initialize filter with include status codes")
    void shouldInitializeFilterWithIncludeStatusCodes() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.INCLUDE_STATUS_CODES, "201,202"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        assertDoesNotThrow(() -> new CustomAccessLogFilter(resolver, null));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "CustomAccessLogFilter initialized");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
    }

    @Test
    @DisplayName("Should initialize filter with custom pattern")
    void shouldInitializeFilterWithCustomPattern() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.PATTERN, "{method} {path} {status}"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        assertDoesNotThrow(() -> new CustomAccessLogFilter(resolver, null));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "CustomAccessLogFilter initialized");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=false");
    }

    @Test
    @DisplayName("Should initialize filter with enabled flag set to true")
    void shouldInitializeFilterWithEnabledFlag() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        assertDoesNotThrow(() -> new CustomAccessLogFilter(resolver, null));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "CustomAccessLogFilter initialized");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "enabled=true");
    }

    @Test
    @DisplayName("Should skip logging when filter is disabled")
    void shouldSkipLoggingWhenDisabled() {
        // Given - disabled filter (default)
        TestConfig config = new TestConfig(Map.of());
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // When - call response filter with mocked contexts
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.replay(requestContext, responseContext);

        // Then - no exception, filter exits early
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));
        EasyMock.verify(requestContext, responseContext);
    }

    @Test
    @DisplayName("Should match include patterns against paths without a leading slash")
    void shouldMatchIncludePatternsWithoutLeadingSlash() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.INCLUDE_PATHS, "/api/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        // UriInfo.getPath() without leading slash — must be normalized before matching /api/**
        EasyMock.expect(uriInfo.getPath()).andReturn("api/test").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("GET").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();
        EasyMock.replay(requestContext, uriInfo, responseContext);

        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));
    }

    @Test
    @DisplayName("Should log access entry when filter is enabled and status matches")
    void shouldLogAccessEntryWhenEnabledAndStatusMatches() {
        // Given - enabled filter with default config (logs 400-599)
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        // Pass null for vertxRequest to cover resolveVertxRemoteAddress null path
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/test").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("GET").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        // Mock response context with 500 status (within default 400-599 range)
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        // Then - verify access log entry was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "GET");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/api/test");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "500");

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should not log when status code is outside configured range")
    void shouldNotLogWhenStatusOutsideRange() {
        // Given - enabled filter with default config (logs 400-599)
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/test").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();

        // Mock response context with 200 status (outside default 400-599 range)
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(200).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should handle null start time gracefully")
    void shouldHandleNullStartTime() {
        // Given - enabled filter
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context with null start time (request filter was not called)
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/error").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("POST").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(null).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn(null).anyTimes();

        // Mock response context with 404 status
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(404).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When - should handle null start time (duration = -1) and null user agent
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        // Then
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "POST");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/api/error");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "404");

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should store start time in request filter when enabled")
    void shouldStoreStartTimeWhenEnabled() {
        // Given - enabled filter
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context that expects setProperty call
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        requestContext.setProperty(EasyMock.eq("cui.access-log.start-time"), EasyMock.anyObject(Instant.class));
        EasyMock.expectLastCall().once();

        EasyMock.replay(requestContext);

        // When - call the request filter
        assertDoesNotThrow(() -> filter.filter(requestContext));

        EasyMock.verify(requestContext);
    }

    @Test
    @DisplayName("Should not store start time in request filter when disabled")
    void shouldNotStoreStartTimeWhenDisabled() {
        // Given - disabled filter (default)
        TestConfig config = new TestConfig(Map.of());
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context - should NOT receive setProperty call
        ContainerRequestContext requestContext = EasyMock.strictMock(ContainerRequestContext.class);
        EasyMock.replay(requestContext);

        // When
        assertDoesNotThrow(() -> filter.filter(requestContext));

        // Then - no interactions expected
        EasyMock.verify(requestContext);
    }

    @Test
    @DisplayName("Should respect path exclusion patterns")
    void shouldRespectPathExclusionPatterns() {
        // Given - enabled filter with path exclusions
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.EXCLUDE_PATHS, "/health/**,/metrics/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context for excluded path
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/health/ready").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();

        // Mock response context with 500 status (would normally be logged)
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When - should not log because path is excluded
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should translate glob patterns to regex with URL-glob semantics")
    void shouldTranslateGlobPatternsToRegex() {
        // ** crosses path segments
        assertTrue(CustomAccessLogFilter.globToRegex("/health/**").matcher("/health/ready").matches());
        assertTrue(CustomAccessLogFilter.globToRegex("/health/**").matcher("/health/live/deep").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/health/**").matcher("/healthz/ready").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/health/**").matcher("/api/health/ready").matches());

        // * stays within a single segment
        assertTrue(CustomAccessLogFilter.globToRegex("/api/*").matcher("/api/users").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/api/*").matcher("/api/users/42").matches());

        // ? matches exactly one non-'/' character
        assertTrue(CustomAccessLogFilter.globToRegex("/api/v?/users").matcher("/api/v1/users").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/api/v?/users").matcher("/api/v12/users").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/api/v?/users").matcher("/api/v//users").matches());

        // Regex metacharacters in patterns are treated literally
        assertTrue(CustomAccessLogFilter.globToRegex("/api/items(1)").matcher("/api/items(1)").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/api/items.json").matcher("/api/itemsXjson").matches());

        // Request paths that would be invalid as filesystem paths must still match
        assertTrue(CustomAccessLogFilter.globToRegex("/api/**").matcher("/api/items/a<b>:c|d").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/other/**").matcher("/api/items/a<b>:c|d").matches());
    }

    @Test
    @DisplayName("Should exclude paths that are not valid filesystem paths")
    void shouldExcludeNonFilesystemSafePaths() {
        // Given - enabled filter excluding /internal/**
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.EXCLUDE_PATHS, "/internal/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        // Mock request context for an excluded path containing characters
        // that are invalid in filesystem paths on some platforms
        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/internal/report<v:1>").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When - must not throw and must not log (path excluded)
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should not log when include patterns are configured but none matches")
    void shouldNotLogWhenNoIncludePatternMatches() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.INCLUDE_PATHS, "/api/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/other/resource").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When - path matches no include pattern, so nothing is logged
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should log non-excluded path when exclude patterns are configured")
    void shouldLogNonExcludedPathWhenExcludesConfigured() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.EXCLUDE_PATHS, "/health/**"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/orders").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("GET").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/api/orders");
        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should log status outside range when listed in include status codes")
    void shouldLogStatusFromIncludeList() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.INCLUDE_STATUS_CODES, "201"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);
        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, null);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/created").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("POST").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        // 201 is below the default 400-599 range but explicitly included
        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(201).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/api/created");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "201");
        EasyMock.verify(requestContext, responseContext, uriInfo);
    }

    @Test
    @DisplayName("Should use Vert.x remote address as fallback client address")
    void shouldUseVertxRemoteAddressAsFallback() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true",
                JwtPropertyKeys.ACCESSLOG.PATTERN, "{method} {path} {status} {remoteAddr}"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        // Vert.x request resolvable through the CDI Instance: its host is the fallback address
        SocketAddress socketAddress = EasyMock.niceMock(SocketAddress.class);
        EasyMock.expect(socketAddress.host()).andReturn("10.20.30.40").anyTimes();
        HttpServerRequest vertxRequest = EasyMock.niceMock(HttpServerRequest.class);
        EasyMock.expect(vertxRequest.remoteAddress()).andReturn(socketAddress).anyTimes();
        @SuppressWarnings("unchecked")
        Instance<HttpServerRequest> vertxInstance = EasyMock.niceMock(Instance.class);
        EasyMock.expect(vertxInstance.isUnsatisfied()).andReturn(false).anyTimes();
        EasyMock.expect(vertxInstance.get()).andReturn(vertxRequest).anyTimes();
        EasyMock.replay(socketAddress, vertxRequest, vertxInstance);

        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, vertxInstance);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/fallback").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("GET").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        // No proxy headers: the Vert.x address must be used
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "10.20.30.40");
        EasyMock.verify(requestContext, responseContext, uriInfo, vertxInstance, vertxRequest, socketAddress);
    }

    @Test
    @DisplayName("Should log with fallback address when Vert.x request resolution fails")
    void shouldHandleVertxRequestResolutionFailure() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.ACCESSLOG.ENABLED, "true"
        ));
        AccessLogFilterConfigResolver resolver = new AccessLogFilterConfigResolver(config);

        // Outside an active request scope, resolving the Vert.x request throws
        @SuppressWarnings("unchecked")
        Instance<HttpServerRequest> vertxInstance = EasyMock.niceMock(Instance.class);
        EasyMock.expect(vertxInstance.isUnsatisfied()).andReturn(false).anyTimes();
        EasyMock.expect(vertxInstance.get())
                .andThrow(new IllegalStateException("no active request context")).anyTimes();
        EasyMock.replay(vertxInstance);

        CustomAccessLogFilter filter = new CustomAccessLogFilter(resolver, vertxInstance);

        ContainerRequestContext requestContext = EasyMock.niceMock(ContainerRequestContext.class);
        UriInfo uriInfo = EasyMock.niceMock(UriInfo.class);
        EasyMock.expect(uriInfo.getPath()).andReturn("/api/no-vertx").anyTimes();
        EasyMock.expect(requestContext.getUriInfo()).andReturn(uriInfo).anyTimes();
        EasyMock.expect(requestContext.getMethod()).andReturn("GET").anyTimes();
        EasyMock.expect(requestContext.getProperty("cui.access-log.start-time"))
                .andReturn(Instant.now()).anyTimes();
        EasyMock.expect(requestContext.getHeaders())
                .andReturn(new MultivaluedHashMap<>()).anyTimes();
        EasyMock.expect(requestContext.getHeaderString("User-Agent"))
                .andReturn("TestAgent/1.0").anyTimes();

        ContainerResponseContext responseContext = EasyMock.niceMock(ContainerResponseContext.class);
        EasyMock.expect(responseContext.getStatus()).andReturn(500).anyTimes();

        EasyMock.replay(requestContext, responseContext, uriInfo);

        // When - resolution failure must be swallowed and the entry still logged
        assertDoesNotThrow(() -> filter.filter(requestContext, responseContext));

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "/api/no-vertx");
        EasyMock.verify(requestContext, responseContext, uriInfo, vertxInstance);
    }

    @Test
    @DisplayName("Should keep single-star glob within one segment when more literal text follows")
    void shouldTranslateMidPatternSingleStar() {
        assertTrue(CustomAccessLogFilter.globToRegex("/api/v*beta").matcher("/api/v2beta").matches());
        assertTrue(CustomAccessLogFilter.globToRegex("/api/v*beta").matcher("/api/vbeta").matches());
        assertFalse(CustomAccessLogFilter.globToRegex("/api/v*beta").matcher("/api/v2/beta").matches());
    }
}