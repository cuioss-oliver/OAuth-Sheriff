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

import de.cuioss.sheriff.token.quarkus.config.AccessLogFilterConfig;
import de.cuioss.sheriff.token.quarkus.config.AccessLogFilterConfigResolver;
import de.cuioss.tools.logging.CuiLogger;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.CreationException;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.regex.Pattern;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * Custom HTTP access log filter with configurable status code and path filtering.
 * This filter provides more granular control than Quarkus built-in access logging,
 * allowing filtering by HTTP status codes and URL patterns.
 *
 * Control via enabled flag: cui.http.access-log.filter.enabled=true
 *
 * Features:
 * - Uses INFO level logging
 * - Filter by HTTP status code ranges
 * - Include/exclude specific status codes
 * - Include/exclude URL path patterns
 * - Configurable log format
 * - Performance optimized with cached disabled state
 *
 * @since 1.0
 */
@Provider
@ApplicationScoped
@RegisterForReflection
public class CustomAccessLogFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final String REQUEST_START_TIME = "cui.access-log.start-time";
    private static final CuiLogger LOGGER = new CuiLogger(CustomAccessLogFilter.class);


    private final AccessLogFilterConfig config;
    private final Instance<HttpServerRequest> vertxRequest;
    private final List<Pattern> includePathPatterns;
    private final List<Pattern> excludePathPatterns;
    private final boolean disabled;

    @Inject
    public CustomAccessLogFilter(AccessLogFilterConfigResolver configResolver,
            Instance<HttpServerRequest> vertxRequest) {
        this.vertxRequest = vertxRequest;
        this.config = configResolver.resolveConfig();

        // Cache disabled state for performance optimization
        this.disabled = !config.isEnabled();

        // Compile and cache path patterns once at construction time
        this.includePathPatterns = compilePathPatterns(config.getIncludePaths());
        this.excludePathPatterns = compilePathPatterns(config.getExcludePaths());

        LOGGER.info(INFO.CUSTOM_ACCESS_LOG_FILTER_INITIALIZED, config);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        // Early exit if disabled - performance optimized with cached state
        if (disabled) {
            return;
        }

        // Store request start time for duration calculation
        requestContext.setProperty(REQUEST_START_TIME, Instant.now());
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        // Early exit if disabled - performance optimized with cached state
        if (disabled) {
            return;
        }

        int statusCode = responseContext.getStatus();
        String path = requestContext.getUriInfo().getPath();

        // Check if this request should be logged
        if (!shouldLog(statusCode, path)) {
            return;
        }

        // Calculate request duration
        Instant startTime = (Instant) requestContext.getProperty(REQUEST_START_TIME);
        long duration = startTime != null ?
                Duration.between(startTime, Instant.now()).toMillis() : -1;

        // Format and log the access entry
        String logEntry = formatLogEntry(requestContext, responseContext, duration);
        LOGGER.info(INFO.ACCESS_LOG_ENTRY, logEntry);
    }

    /**
     * Determines if a request should be logged based on status code and path.
     */
    private boolean shouldLog(int statusCode, String path) {
        // Check path inclusion/exclusion first (cheaper than status code checks)
        if (!isPathIncluded(path)) {
            return false;
        }

        // Check if status code is in the configured range
        if (statusCode >= config.getMinStatusCode() && statusCode <= config.getMaxStatusCode()) {
            return true;
        }

        // Check if status code is in the explicit include list
        return config.getIncludeStatusCodes().contains(statusCode);
    }

    /**
     * Checks if a path should be included in logging based on include/exclude patterns.
     * Matches against the raw request path string — no filesystem semantics are involved.
     */
    private boolean isPathIncluded(String path) {
        // JAX-RS implementations differ on whether UriInfo.getPath() carries a leading
        // slash; configured patterns conventionally do — normalize before matching
        String normalizedPath = path.startsWith("/") ? path : "/" + path;

        // Check exclude patterns first (take precedence)
        for (Pattern pattern : excludePathPatterns) {
            if (pattern.matcher(normalizedPath).matches()) {
                return false;
            }
        }

        // If no include patterns specified, all paths are included
        if (includePathPatterns.isEmpty()) {
            return true;
        }

        // Check include patterns
        for (Pattern pattern : includePathPatterns) {
            if (pattern.matcher(normalizedPath).matches()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Formats the log entry according to the configured pattern.
     */
    private String formatLogEntry(ContainerRequestContext requestContext,
            ContainerResponseContext responseContext,
            long duration) {
        String pattern = config.getPattern();
        String fallbackAddr = resolveVertxRemoteAddress();
        String remoteAddr = ClientIpExtractor.extractClientIp(requestContext.getHeaders(), fallbackAddr);
        String userAgent = requestContext.getHeaderString("User-Agent");

        return pattern
                .replace("{method}", requestContext.getMethod())
                .replace("{path}", requestContext.getUriInfo().getPath())
                .replace("{status}", String.valueOf(responseContext.getStatus()))
                .replace("{duration}", String.valueOf(duration))
                .replace("{remoteAddr}", remoteAddr)
                .replace("{userAgent}", userAgent != null ? userAgent : "-");
    }

    private static List<Pattern> compilePathPatterns(List<String> patterns) {
        return patterns.stream()
                .map(CustomAccessLogFilter::globToRegex)
                .toList();
    }

    /**
     * Translates a URL glob pattern to a precompiled regular expression.
     * <p>
     * Supported glob semantics:
     * <ul>
     *   <li>{@code **} — matches any number of characters, crossing path segments</li>
     *   <li>{@code *} — matches any number of characters within a single segment (no {@code /})</li>
     *   <li>{@code ?} — matches exactly one character within a segment (no {@code /})</li>
     * </ul>
     * All other characters are matched literally (regex metacharacters are escaped).
     * The pattern must match the entire request path.
     *
     * @param glob the glob pattern, e.g. {@code /health/**}
     * @return the compiled regex pattern
     */
    static Pattern globToRegex(String glob) {
        StringBuilder regex = new StringBuilder();
        int i = 0;
        while (i < glob.length()) {
            char c = glob.charAt(i);
            switch (c) {
                case '*' -> {
                    if (i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                        regex.append(".*");
                        i++;
                    } else {
                        regex.append("[^/]*");
                    }
                }
                case '?' -> regex.append("[^/]");
                default -> {
                    if ("\\^$.|+()[]{}".indexOf(c) >= 0) {
                        regex.append('\\');
                    }
                    regex.append(c);
                }
            }
            i++;
        }
        return Pattern.compile(regex.toString());
    }

    /**
     * Resolves the direct TCP remote address from the Vert.x request context.
     * Used as fallback when no proxy headers are present.
     *
     * @return the remote address host, or {@code null} if unavailable
     */
    private String resolveVertxRemoteAddress() {
        try {
            if (vertxRequest != null && !vertxRequest.isUnsatisfied()) {
                var request = vertxRequest.get();
                if (request != null && request.remoteAddress() != null) {
                    return request.remoteAddress().host();
                }
            }
        } catch (IllegalStateException | CreationException e) {
            LOGGER.debug(e, "Could not resolve Vert.x remote address");
        }
        return null;
    }

}