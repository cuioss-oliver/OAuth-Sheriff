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
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Configuration parameters for the {@code HttpJwksLoader} (the JWKS crypto orchestrator in the
 * {@code validation} layer, which depends down on this transport configuration).
 * <p>
 * This class encapsulates configuration options for the HttpJwksLoader,
 * including JWKS endpoint URL, refresh interval, SSL context, and
 * background refresh parameters. The JWKS endpoint URL can be configured
 * directly or discovered via a {@link WellKnownConfig}.
 * <p>
 * Complex caching parameters (maxCacheSize, adaptiveWindowSize) have been
 * removed for simplification while keeping essential refresh functionality.
 * <p>
 * For more detailed information about the HTTP-based JWKS loading, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#_jwksloader">Technical Components Specification</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class HttpJwksLoaderConfig {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoaderConfig.class);

    /**
     * A Default of 10 minutes (600 seconds).
     */
    private static final int DEFAULT_REFRESH_INTERVAL_IN_SECONDS = 60 * 10;

    /**
     * Default key rotation grace period of 5 minutes (as per Issue #110).
     */
    private static final Duration DEFAULT_KEY_ROTATION_GRACE_PERIOD = Duration.ofMinutes(5);

    /**
     * Default maximum number of retired key sets to keep.
     */
    private static final int DEFAULT_MAX_RETIRED_KEY_SETS = 3;

    /**
     * Default connect timeout in seconds (2) for the direct-JWKS transport, set explicitly to match
     * the discovery transport defaults in {@link WellKnownConfig} rather than silently inheriting the
     * laxer cui-http 10-second default. Keeping the JWKS and discovery timeouts consistent gives both
     * IdP-advertised fetches the same tight DoS bound (M8).
     */
    private static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 2;

    /**
     * Default read timeout in seconds (3) for the direct-JWKS transport, set explicitly to match the
     * discovery transport defaults in {@link WellKnownConfig}. See {@link #DEFAULT_CONNECT_TIMEOUT_SECONDS}.
     */
    private static final int DEFAULT_READ_TIMEOUT_SECONDS = 3;

    /**
     * The interval in seconds at which to refresh the keys.
     * If set to 0, no time-based caching will be used.
     * It defaults to 10 minutes (600 seconds).
     */
    @Getter
    private final int refreshIntervalSeconds;

    /**
     * The HttpHandler used for HTTP requests.
     * <p>
     * This field is guaranteed to be non-null when using direct JWKS URI configuration.
     * It will be null only when using WellKnownConfig for discovery.
     * <p>
     * The non-null contract for HTTP configurations is enforced by the {@link HttpJwksLoaderConfigBuilder#build()}
     * method, which validates that the HttpHandler was successfully created before constructing the config.
     */
    @EqualsAndHashCode.Exclude
    private final HttpHandler httpHandler;

    /**
     * The WellKnownConfig used for well-known endpoint discovery.
     * Will be null if using direct HttpHandler.
     * Contains all configuration needed to load well-known configuration.
     */
    @Getter
    @EqualsAndHashCode.Exclude
    private final WellKnownConfig wellKnownConfig;

    /**
     * The retry configuration for HTTP operations.
     */
    @Getter
    private final RetryConfig retryConfig;

    /**
     * The ScheduledExecutorService used for background refresh operations.
     * Can be null if no background refresh is needed.
     */
    @Getter
    @EqualsAndHashCode.Exclude
    private final ScheduledExecutorService scheduledExecutorService;

    /**
     * Whether this config owns the executor (auto-created) and should shut it down on close.
     */
    @Getter
    private final boolean ownsExecutor;

    /**
     * The issuer identifier for this JWKS configuration.
     * Used for logging and identification purposes.
     */
    @Getter
    private final String issuerIdentifier;

    /**
     * The grace period for keeping retired key sets after rotation.
     */
    @Getter
    private final Duration keyRotationGracePeriod;

    /**
     * Maximum number of retired key sets to keep.
     */
    @Getter
    private final int maxRetiredKeySets;

    /**
     * The parser configuration for JSON parsing (DSL-JSON).
     * <p>
     * This is pre-initialized on the caller's thread to ensure the correct
     * classloader is used for ServiceLoader discovery, avoiding issues with
     * ForkJoinPool threads that may have a different classloader context
     * (e.g., in NiFi's NAR classloading model).
     */
    @Getter
    @EqualsAndHashCode.Exclude
    private final ParserConfig parserConfig;

    /**
     * The SSRF egress policy applied to the advertised/configured JWKS URL immediately
     * before it is fetched. Defaults to {@link EgressPolicy#secureDefault()} (loopback and
     * all internal ranges rejected); relaxed only via the explicit
     * {@link HttpJwksLoaderConfigBuilder#allowLoopbackEgress(boolean)} knob.
     */
    @Getter
    @EqualsAndHashCode.Exclude
    private final EgressPolicy egressPolicy;

    @SuppressWarnings("java:S107") // ok for builder
    private HttpJwksLoaderConfig(int refreshIntervalSeconds,
            HttpHandler httpHandler,
            WellKnownConfig wellKnownConfig,
            RetryConfig retryConfig,
            ScheduledExecutorService scheduledExecutorService,
            boolean ownsExecutor,
            String issuerIdentifier,
            Duration keyRotationGracePeriod,
            int maxRetiredKeySets,
            ParserConfig parserConfig,
            EgressPolicy egressPolicy) {
        this.refreshIntervalSeconds = refreshIntervalSeconds;
        this.httpHandler = httpHandler;
        this.wellKnownConfig = wellKnownConfig;
        this.retryConfig = retryConfig;
        this.scheduledExecutorService = scheduledExecutorService;
        this.ownsExecutor = ownsExecutor;
        this.issuerIdentifier = issuerIdentifier;
        this.keyRotationGracePeriod = keyRotationGracePeriod;
        this.maxRetiredKeySets = maxRetiredKeySets;
        this.parserConfig = parserConfig;
        this.egressPolicy = egressPolicy;
    }

    /**
     * Provides the HttpHandler for HTTP operations, implementing HttpHandlerProvider interface.
     * <p>
     * This method handles both configuration modes:
     * <ul>
     *   <li><strong>Direct HTTP mode</strong>: Returns the configured HttpHandler</li>
     *   <li><strong>WellKnown mode</strong>: Returns the HttpHandler from the WellKnownConfig</li>
     * </ul>
     *
     * @return the HttpHandler instance, never null
     * @throws IllegalStateException if no HttpHandler is available in either mode
     */
    public HttpHandler getHttpHandler() {
        if (httpHandler != null) {
            // Direct HTTP mode - return the configured HttpHandler
            return httpHandler;
        } else if (wellKnownConfig != null) {
            // WellKnown mode - get HttpHandler from the WellKnownConfig
            return wellKnownConfig.getHttpHandler();
        } else {
            throw new IllegalStateException("Neither HttpHandler nor WellKnownConfig is configured");
        }
    }


    /**
     * Creates a new HttpHandler for the given URL using configured values.
     * This overloaded method centralizes HttpHandler creation with consistent settings
     * based on the current configuration instance.
     *
     * @param url the URL to create a handler for
     * @return a new HttpHandler instance with configured settings
     */
   
    public HttpHandler getHttpHandler(String url) {
        // Reuse existing HttpHandler configuration as base
        HttpHandler baseHandler = getHttpHandler();

        // Create a new handler with the same configuration but different URL.
        // asBuilder() copies the base handler's settings (including allowInsecureHttp),
        // so the caller's security preference is preserved.
        HttpHandler handler = baseHandler.asBuilder()
                .url(url)
                .build();

        // Emit the insecure-HTTP warning for JWKS URLs discovered via well-known lookup,
        // mirroring the direct-configuration path in build().
        if ("http".equalsIgnoreCase(handler.getUri().getScheme())) {
            LOGGER.warn(TransportLogMessages.WARN.INSECURE_HTTP_JWKS, handler.getUri().toString());
        }
        return handler;
    }

    /**
     * Determines if background refresh is enabled based on configuration.
     * Background refresh is enabled when both a ScheduledExecutorService is configured
     * and the refresh interval is greater than 0.
     *
     * @return true if background refresh should be enabled, false otherwise
     */
    public boolean isBackgroundRefreshEnabled() {
        return scheduledExecutorService != null && refreshIntervalSeconds > 0;
    }

    /**
     * Gets the JWKS type based on configuration.
     * Returns WELL_KNOWN if using well-known discovery, HTTP if using direct endpoint.
     *
     * @return the JwksType for this configuration
     */
   
    public JwksType getJwksType() {
        return wellKnownConfig != null ? JwksType.WELL_KNOWN : JwksType.HTTP;
    }

    /**
     * Creates a new builder for HttpJwksLoaderConfig.
     * <p>
     * This method provides a convenient way to create a new instance of
     * HttpJwksLoaderConfigBuilder, allowing for fluent configuration of the
     * HttpJwksLoaderConfig parameters.
     *
     * @return a new HttpJwksLoaderConfigBuilder instance
     */
    public static HttpJwksLoaderConfigBuilder builder() {
        return new HttpJwksLoaderConfigBuilder();
    }

    /**
     * Enum to track which endpoint configuration method was used.
     */
    private enum EndpointSource {
        JWKS_URI,
        JWKS_URL,
        WELL_KNOWN_URL,
        WELL_KNOWN_URI
    }

    /**
     * Builder for creating HttpJwksLoaderConfig instances with validation.
     */
    public static class HttpJwksLoaderConfigBuilder {
        private Integer refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_IN_SECONDS;
        private final HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private RetryConfig retryConfig;
        private ScheduledExecutorService scheduledExecutorService;
        private String issuerIdentifier;
        private Duration keyRotationGracePeriod = DEFAULT_KEY_ROTATION_GRACE_PERIOD;
        private int maxRetiredKeySets = DEFAULT_MAX_RETIRED_KEY_SETS;
        private ParserConfig parserConfig;
        private boolean allowInsecureHttp = false;
        private boolean allowLoopbackEgress = false;
        private final List<String> allowedEgressHosts = new ArrayList<>();

        // Pending well-known values — WellKnownConfig creation is deferred to build()
        private String pendingWellKnownUrl;
        private URI pendingWellKnownUri;

        // Track which endpoint configuration method was used to ensure mutual exclusivity
        private EndpointSource endpointSource = null;

        /**
         * Constructor initializing the HttpHandlerBuilder.
         */
        public HttpJwksLoaderConfigBuilder() {
            // Apply explicit, documented timeout defaults consistent with the discovery transport
            // (WellKnownConfig) so the JWKS fetch does not silently inherit cui-http's laxer 10s/10s
            // defaults (M8). A later connectTimeoutSeconds()/readTimeoutSeconds() call overrides these.
            this.httpHandlerBuilder = HttpHandler.builder()
                    .connectionTimeoutSeconds(DEFAULT_CONNECT_TIMEOUT_SECONDS)
                    .readTimeoutSeconds(DEFAULT_READ_TIMEOUT_SECONDS);
        }

        /**
         * Controls whether plaintext {@code http://} JWKS endpoints are permitted.
         * <p>
         * Defaults to {@code false} (secure by default): {@link #build()} rejects
         * {@code http://} JWKS endpoints so key material cannot be substituted via a
         * man-in-the-middle downgrade. Set to {@code true} to opt into cleartext HTTP —
         * accepted but with a {@code TokenSheriff-139} ({@code INSECURE_HTTP_JWKS})
         * warning — which should only be used for local development or trusted-network
         * scenarios, never in production.
         *
         * @param allowInsecureHttp {@code true} to opt into cleartext HTTP, {@code false} (default) to require HTTPS
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder allowInsecureHttp(boolean allowInsecureHttp) {
            this.allowInsecureHttp = allowInsecureHttp;
            return this;
        }

        /**
         * Permits the SSRF egress guard to resolve the JWKS URL to a loopback address.
         * <p>
         * Defaults to {@code false}: the secure-by-default {@link EgressPolicy} rejects
         * loopback, link-local, site-local, ULA, and cloud-metadata addresses so an
         * attacker-advertised {@code jwks_uri} cannot reach internal endpoints. Set to
         * {@code true} to fetch JWKS from {@code localhost} — required by MockWebServer-based
         * tests and local/dev callers, which must opt in deliberately. This is an explicit,
         * discoverable knob, never an implicit test-mode; all other blocked ranges still apply.
         *
         * @param allowLoopbackEgress {@code true} to allow loopback JWKS fetches, {@code false} (default) to reject them
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder allowLoopbackEgress(boolean allowLoopbackEgress) {
            this.allowLoopbackEgress = allowLoopbackEgress;
            return this;
        }

        /**
         * Adds a host to the SSRF egress guard's explicit allow-list for both the advertised
         * {@code jwks_uri} fetch and, in well-known mode, the discovery fetch.
         * <p>
         * Allow-listed hosts bypass the address-range checks entirely, so a JWKS or discovery
         * endpoint whose host resolves to a site-local, link-local, or ULA address (for example
         * a Docker service name such as {@code keycloak} on a container bridge network) can be
         * reached despite the secure-by-default {@link EgressPolicy}. Matching is case-insensitive.
         * This is an explicit, discoverable knob intended for integration tests and trusted
         * local/dev topologies; it must be scoped narrowly and never used to allow-list
         * attacker-influenceable hosts in production.
         *
         * @param host the host name to allow-list; ignored when {@code null} or blank
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder allowedEgressHost(String host) {
            if (host != null && !host.isBlank()) {
                allowedEgressHosts.add(host);
            }
            return this;
        }

        /**
         * Sets the issuer identifier for this JWKS configuration.
         * Used for logging and identification purposes.
         *
         * @param issuerIdentifier the issuer identifier
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder issuerIdentifier(String issuerIdentifier) {
            this.issuerIdentifier = issuerIdentifier;
            return this;
        }

        /**
         * Sets the key rotation grace period.
         * Defaults to 5 minutes if not specified.
         *
         * @param keyRotationGracePeriod the grace period duration
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder keyRotationGracePeriod(Duration keyRotationGracePeriod) {
            Preconditions.checkArgument(!keyRotationGracePeriod.isNegative(), "keyRotationGracePeriod must not be negative");
            this.keyRotationGracePeriod = keyRotationGracePeriod;
            return this;
        }

        /**
         * Sets the maximum number of retired key sets to keep.
         * Defaults to 3 if not specified.
         *
         * @param maxRetiredKeySets the maximum number of retired key sets
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder maxRetiredKeySets(int maxRetiredKeySets) {
            Preconditions.checkArgument(maxRetiredKeySets > 0, "maxRetiredKeySets must be positive");
            this.maxRetiredKeySets = maxRetiredKeySets;
            return this;
        }

        /**
         * Sets a pre-initialized ParserConfig for JSON parsing.
         * <p>
         * When set, this ParserConfig will be used for both JWKS content parsing
         * and well-known discovery parsing, avoiding ServiceLoader calls on
         * ForkJoinPool threads that may have the wrong classloader.
         * </p>
         * <p>
         * If not set, a default ParserConfig will be created during {@link #build()}.
         * </p>
         *
         * @param parserConfig the pre-initialized parser configuration
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }

        /**
         * Sets the JWKS URI directly.
         * <p>
         * This method is mutually exclusive with {@link #jwksUrl(String)}, {@link #wellKnownUrl(String)}, and {@link #wellKnownUri(URI)}.
         * Only one endpoint configuration method can be used per builder instance.
         * </p>
         *
         * @param jwksUri the URI of the JWKS endpoint. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if another endpoint configuration method was already used
         */
        public HttpJwksLoaderConfigBuilder jwksUri(URI jwksUri) {
            validateEndpointExclusivity(EndpointSource.JWKS_URI);
            this.endpointSource = EndpointSource.JWKS_URI;
            httpHandlerBuilder.uri(jwksUri);
            return this;
        }

        /**
         * Sets the JWKS URL as a string, which will be converted to a URI.
         * <p>
         * This method is mutually exclusive with {@link #jwksUri(URI)}, {@link #wellKnownUrl(String)}, and {@link #wellKnownUri(URI)}.
         * Only one endpoint configuration method can be used per builder instance.
         * </p>
         *
         * @param jwksUrl the URL string of the JWKS endpoint. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if another endpoint configuration method was already used
         */
        public HttpJwksLoaderConfigBuilder jwksUrl(String jwksUrl) {
            validateEndpointExclusivity(EndpointSource.JWKS_URL);
            this.endpointSource = EndpointSource.JWKS_URL;
            httpHandlerBuilder.url(jwksUrl);
            return this;
        }

        /**
         * Configures the JWKS loading using well-known endpoint discovery from a URL string.
         * <p>
         * This method creates a {@link WellKnownConfig} internally for dynamic JWKS URI resolution.
         * The JWKS URI will be extracted at runtime from the well-known discovery document.
         * </p>
         * <p>
         * This method is mutually exclusive with {@link #jwksUri(URI)}, {@link #jwksUrl(String)}, and {@link #wellKnownUri(URI)}.
         * Only one endpoint configuration method can be used per builder instance.
         * </p>
         *
         * @param wellKnownUrl The well-known discovery endpoint URL string. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if another endpoint configuration method was already used
         * @throws IllegalArgumentException if {@code wellKnownUrl} is null or invalid
         */
        public HttpJwksLoaderConfigBuilder wellKnownUrl(String wellKnownUrl) {
            validateEndpointExclusivity(EndpointSource.WELL_KNOWN_URL);
            this.endpointSource = EndpointSource.WELL_KNOWN_URL;
            this.pendingWellKnownUrl = wellKnownUrl;
            return this;
        }

        /**
         * Configures the JWKS loading using well-known endpoint discovery from a URI.
         * <p>
         * This method creates a {@link WellKnownConfig} internally for dynamic JWKS URI resolution.
         * The JWKS URI will be extracted at runtime from the well-known discovery document.
         * </p>
         * <p>
         * This method is mutually exclusive with {@link #jwksUri(URI)}, {@link #jwksUrl(String)}, and {@link #wellKnownUrl(String)}.
         * Only one endpoint configuration method can be used per builder instance.
         * </p>
         *
         * @param wellKnownUri The well-known discovery endpoint URI. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if another endpoint configuration method was already used
         * @throws IllegalArgumentException if {@code wellKnownUri} is null
         */
        public HttpJwksLoaderConfigBuilder wellKnownUri(URI wellKnownUri) {
            validateEndpointExclusivity(EndpointSource.WELL_KNOWN_URI);
            this.endpointSource = EndpointSource.WELL_KNOWN_URI;
            this.pendingWellKnownUri = wellKnownUri;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider the TLS versions configuration to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        /**
         * Sets the refresh interval in seconds.
         * <p>
         * If set to 0, no time-based caching will be used. It defaults to 10 minutes (600 seconds).
         * </p>
         *
         * @param refreshIntervalSeconds the refresh interval in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if a refresh interval is negative
         */
        public HttpJwksLoaderConfigBuilder refreshIntervalSeconds(int refreshIntervalSeconds) {
            Preconditions.checkArgument(refreshIntervalSeconds > -1, "refreshIntervalSeconds must be zero or positive");
            this.refreshIntervalSeconds = refreshIntervalSeconds;
            return this;
        }


        /**
         * Sets the SSL context to use for HTTPS connections.
         * <p>
         * If not set, a default secure SSL context will be created.
         * </p>
         *
         * @param sslContext The SSL context to use.
         * @return This builder instance.
         */
        public HttpJwksLoaderConfigBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        /**
         * Sets the connection timeout in seconds.
         *
         * @param connectTimeoutSeconds the connection timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if connectTimeoutSeconds is not positive
         */
        public HttpJwksLoaderConfigBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            Preconditions.checkArgument(connectTimeoutSeconds > 0, "connectTimeoutSeconds must be > 0, but was %s", connectTimeoutSeconds);
            httpHandlerBuilder.connectionTimeoutSeconds(connectTimeoutSeconds);
            return this;
        }

        /**
         * Sets the read timeout in seconds.
         *
         * @param readTimeoutSeconds the read timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if readTimeoutSeconds is not positive
         */
        public HttpJwksLoaderConfigBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            Preconditions.checkArgument(readTimeoutSeconds > 0, "readTimeoutSeconds must be > 0, but was %s", readTimeoutSeconds);
            httpHandlerBuilder.readTimeoutSeconds(readTimeoutSeconds);
            return this;
        }

        /**
         * Sets the retry configuration for HTTP operations.
         *
         * @param retryConfig the retry configuration to use for HTTP requests
         * @return this builder instance
         * @throws IllegalArgumentException if retryConfig is null
         */
        public HttpJwksLoaderConfigBuilder retryConfig(RetryConfig retryConfig) {
            this.retryConfig = retryConfig;
            return this;
        }

        /**
         * Sets the ScheduledExecutorService for background refresh operations.
         *
         * @param scheduledExecutorService the executor service to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder scheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
            this.scheduledExecutorService = scheduledExecutorService;
            return this;
        }

        /**
         * Validates that the proposed endpoint source doesn't conflict with an already configured one.
         * <p>
         * This validation ensures mutual exclusivity between direct JWKS endpoint configuration
         * and well-known discovery configuration. When using well-known discovery, the issuer identifier
         * is automatically provided by the discovery document and cannot be manually configured.
         * </p>
         *
         * @param proposedSource the endpoint source that is being configured
         * @throws IllegalArgumentException if another endpoint configuration method was already used
         */
        private void validateEndpointExclusivity(EndpointSource proposedSource) {
            if (endpointSource != null && endpointSource != proposedSource) {
                throw new IllegalArgumentException(
                        """
                                Cannot use %s endpoint configuration when %s was already configured. \
                                Methods jwksUri(), jwksUrl(), wellKnownUrl(), and wellKnownUri() are mutually exclusive. \
                                When using well-known discovery, the issuer identifier is automatically provided by the discovery document."""
                                .formatted(proposedSource.name().toLowerCase().replace("_", ""), endpointSource.name().toLowerCase().replace("_", "")));
            }
        }

        /**
         * Builds a new HttpJwksLoaderConfig instance with the configured parameters.
         * Validates all parameters and applies default values where appropriate.
         *
         * @return a new HttpJwksLoaderConfig instance
         * @throws IllegalArgumentException if any parameter is invalid
         * @throws IllegalArgumentException if no endpoint was configured
         */
        @SuppressWarnings({"java:S3776", "java:S6541"}) // ok for builder — validation/defaulting inherent to a single build() entry point
        public HttpJwksLoaderConfig build() {
            // Ensure at least one endpoint configuration method was used
            if (endpointSource == null) {
                throw new IllegalArgumentException(
                        "No JWKS endpoint configured. Must call one of: jwksUri(), jwksUrl(), wellKnownUrl(), or wellKnownUri()");
            }

            // Ensure RetryConfig is configured
            if (retryConfig == null) {
                retryConfig = RetryConfig.defaults();
            }

            // Resolve ParserConfig — use provided or create default
            ParserConfig resolvedParserConfig = this.parserConfig != null
                    ? this.parserConfig : ParserConfig.builder().build();

            HttpHandler jwksHttpHandler = null;
            WellKnownConfig configuredWellKnownConfig = null;
            if (endpointSource == EndpointSource.WELL_KNOWN_URL || endpointSource == EndpointSource.WELL_KNOWN_URI) {
                // Build WellKnownConfig with the resolved ParserConfig
                var wkBuilder = WellKnownConfig.builder()
                        .retryConfig(RetryConfig.defaults())
                        .parserConfig(resolvedParserConfig)
                        .allowInsecureHttp(allowInsecureHttp)
                        .allowLoopbackEgress(allowLoopbackEgress);
                for (String allowedHost : allowedEgressHosts) {
                    wkBuilder.allowedEgressHost(allowedHost);
                }
                if (pendingWellKnownUrl != null) {
                    wkBuilder.wellKnownUrl(pendingWellKnownUrl);
                } else {
                    wkBuilder.wellKnownUri(pendingWellKnownUri);
                }
                configuredWellKnownConfig = wkBuilder.build();
            } else {
                // Build the HttpHandler for direct URL/URI configuration
                try {
                    httpHandlerBuilder.allowInsecureHttp(allowInsecureHttp);
                    jwksHttpHandler = httpHandlerBuilder.build();

                    // Check for insecure HTTP protocol
                    URI uri = jwksHttpHandler.getUri();
                    if ("http".equalsIgnoreCase(uri.getScheme())) {
                        LOGGER.warn(TransportLogMessages.WARN.INSECURE_HTTP_JWKS, uri.toString());
                    }
                } catch (IllegalArgumentException | IllegalStateException e) {
                    LOGGER.warn(TransportLogMessages.WARN.INVALID_JWKS_URI);
                    throw new IllegalArgumentException("Invalid URL or HttpHandler configuration", e);
                }
            }

            // Create default ScheduledExecutorService if not provided and refresh interval > 0
            ScheduledExecutorService executor = this.scheduledExecutorService;
            boolean executorOwned = false;
            if (executor == null && refreshIntervalSeconds > 0) {
                String hostName = jwksHttpHandler != null ? jwksHttpHandler.getUri().getHost() : "wellknown";
                executor = Executors.newScheduledThreadPool(1, r -> {
                    Thread t = new Thread(r, "jwks-refresh-" + hostName);
                    t.setDaemon(true);
                    return t;
                });
                executorOwned = true;
            }

            // Validate issuer requirement
            if (configuredWellKnownConfig == null && jwksHttpHandler != null && issuerIdentifier == null) {
                throw new IllegalArgumentException("Issuer identifier is mandatory when using direct JWKS configuration");
            }

            // For well-known, issuer will be discovered dynamically during resolution (optional in config)

            EgressPolicy.EgressPolicyBuilder egressPolicyBuilder = EgressPolicy.builder()
                    .allowLoopback(allowLoopbackEgress);
            for (String allowedHost : allowedEgressHosts) {
                egressPolicyBuilder.allowedHost(allowedHost);
            }
            EgressPolicy resolvedEgressPolicy = egressPolicyBuilder.build();

            return new HttpJwksLoaderConfig(
                    refreshIntervalSeconds,
                    jwksHttpHandler,
                    configuredWellKnownConfig,
                    retryConfig,
                    executor,
                    executorOwned,
                    issuerIdentifier,
                    keyRotationGracePeriod,
                    maxRetiredKeySets,
                    resolvedParserConfig,
                    resolvedEgressPolicy);
        }

    }

}