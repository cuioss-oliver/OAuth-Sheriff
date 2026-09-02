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
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for well-known endpoint discovery.
 * <p>
 * This class encapsulates all configuration parameters needed to create a
 * WellKnownConfig for OIDC endpoint discovery.
 * It uses an internal {@link HttpHandler} built with sensible defaults while allowing
 * customization of timeouts, SSL context, and parser configuration.
 * <p>
 * The configuration supports both String URLs and URI objects for the well-known endpoint,
 * and provides comprehensive SSL/TLS configuration options through the HttpHandler builder pattern.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class WellKnownConfig {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownConfig.class);

    /**
     * Default connect timeout in seconds for well-known endpoint requests.
     */
    private static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 2;

    /**
     * Default read timeout in seconds for well-known endpoint requests.
     */
    private static final int DEFAULT_READ_TIMEOUT_SECONDS = 3;

    /**
     * The HTTP handler for well-known endpoint requests.
     */
    @Getter
    private final HttpHandler httpHandler;

    /**
     * The retry configuration for HTTP operations.
     */
    @Getter
    private final RetryConfig retryConfig;

    /**
     * Parser configuration for JSON processing.
     */
    @Getter
    private final ParserConfig parserConfig;

    /**
     * The SSRF egress policy applied to the discovery endpoint before it is fetched.
     * Defaults to {@link EgressPolicy#secureDefault()}; relaxed only via the explicit
     * {@link WellKnownConfigBuilder#allowLoopbackEgress(boolean)} knob.
     */
    @Getter
    private final EgressPolicy egressPolicy;

    private WellKnownConfig(HttpHandler httpHandler, RetryConfig retryConfig, ParserConfig parserConfig, EgressPolicy egressPolicy) {
        this.httpHandler = httpHandler;
        this.retryConfig = retryConfig;
        this.parserConfig = parserConfig;
        this.egressPolicy = egressPolicy;
    }

    /**
     * Creates a new HttpWellKnownResolver using this configuration.
     *
     * @param securityEventCounter the shared security event counter
     * @return a configured HttpWellKnownResolver instance
     */
    public HttpWellKnownResolver createResolver(SecurityEventCounter securityEventCounter) {
        return new HttpWellKnownResolver(this, securityEventCounter);
    }

    /**
     * Creates a new builder for WellKnownConfig.
     *
     * @return a new WellKnownConfigBuilder instance
     */
    public static WellKnownConfigBuilder builder() {
        return new WellKnownConfigBuilder();
    }

    /**
     * Builder for creating WellKnownConfig instances using HttpHandler builder pattern.
     */
    public static class WellKnownConfigBuilder {
        private final HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private RetryConfig retryConfig = RetryConfig.defaults();
        private ParserConfig parserConfig;
        private boolean allowInsecureHttp = false;
        private boolean allowLoopbackEgress = false;
        private boolean verifyHostname = true;
        /**
         * Tracks whether the caller supplied an {@link SSLContext} of their own. {@link #sslContext(SSLContext)}
         * is a pass-through to {@link #httpHandlerBuilder} and keeps no locally readable state, so this flag is
         * what lets {@link #build()} reject the {@code verifyHostname(false)} combination with a first-class
         * message instead of letting it surface as a malformed-endpoint error.
         */
        private boolean sslContextSupplied = false;
        private final List<String> allowedEgressHosts = new ArrayList<>();

        /**
         * Constructor initializing the HttpHandlerBuilder with sensible defaults.
         */
        public WellKnownConfigBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder()
                    .connectionTimeoutSeconds(DEFAULT_CONNECT_TIMEOUT_SECONDS)
                    .readTimeoutSeconds(DEFAULT_READ_TIMEOUT_SECONDS);
        }

        /**
         * Controls whether plaintext {@code http://} discovery endpoints are permitted.
         * <p>
         * Defaults to {@code false} (secure by default): {@link #build()} rejects
         * {@code http://} discovery endpoints so discovery metadata cannot be tampered
         * with via a man-in-the-middle downgrade. Set to {@code true} to opt into
         * cleartext HTTP — accepted but with a {@code TokenSheriff-129}
         * ({@code INSECURE_HTTP_WELLKNOWN}) warning — which should only be used for local
         * development or trusted-network scenarios, never in production.
         *
         * @param allowInsecureHttp {@code true} to opt into cleartext HTTP, {@code false} (default) to require HTTPS
         * @return this builder instance
         */
        public WellKnownConfigBuilder allowInsecureHttp(boolean allowInsecureHttp) {
            this.allowInsecureHttp = allowInsecureHttp;
            return this;
        }

        /**
         * Controls whether TLS hostname verification is performed for the discovery fetch.
         * <p>
         * Defaults to {@code true} (secure by default). Setting this to {@code false} relaxes
         * <strong>hostname matching only</strong> — certificate chain trust, expiry, and algorithm
         * constraints all remain fully enforced, so an untrusted or expired certificate is still
         * rejected.
         * <p>
         * This knob cannot be combined with {@link #sslContext(SSLContext)}. The relaxation applies only
         * to the default-trust-store context the underlying HTTP handler derives, so a caller-supplied
         * context leaves nothing to relax; {@link #build()} rejects the combination with an
         * {@link IllegalArgumentException}. When verification is disabled, trust material must therefore
         * be supplied through the JVM default trust store.
         * <p>
         * <strong>Never set this to {@code false} in production.</strong> Disabling hostname verification
         * removes the guarantee that the certificate presented belongs to the host actually contacted,
         * which re-opens the man-in-the-middle vector that chain validation alone does not close. It
         * exists for local development and test topologies serving SAN-mismatched certificates.
         *
         * @param verifyHostname {@code false} to relax hostname matching, {@code true} (default) to enforce it
         * @return this builder instance
         */
        public WellKnownConfigBuilder verifyHostname(boolean verifyHostname) {
            this.verifyHostname = verifyHostname;
            return this;
        }

        /**
         * Permits the SSRF egress guard to resolve the discovery endpoint to a loopback
         * address.
         * <p>
         * Defaults to {@code false}: the secure-by-default {@link EgressPolicy} rejects
         * loopback, link-local, site-local, ULA, and cloud-metadata addresses so an
         * attacker-controlled discovery URL cannot reach internal endpoints. Set to
         * {@code true} to fetch discovery from {@code localhost} — required by
         * MockWebServer-based tests and local/dev callers, which must opt in deliberately.
         * This is an explicit, discoverable knob, never an implicit test-mode; all other
         * blocked ranges still apply.
         *
         * @param allowLoopbackEgress {@code true} to allow loopback discovery fetches, {@code false} (default) to reject them
         * @return this builder instance
         */
        public WellKnownConfigBuilder allowLoopbackEgress(boolean allowLoopbackEgress) {
            this.allowLoopbackEgress = allowLoopbackEgress;
            return this;
        }

        /**
         * Adds a host to the SSRF egress guard's explicit allow-list for the discovery fetch.
         * <p>
         * Allow-listed hosts bypass the address-range checks entirely, so a discovery endpoint
         * whose host resolves to a site-local, link-local, or ULA address (for example a Docker
         * service name such as {@code keycloak} on a container bridge network) can be reached
         * despite the secure-by-default {@link EgressPolicy}. Matching is case-insensitive.
         * This is an explicit, discoverable knob intended for integration tests and trusted
         * local/dev topologies; it must be scoped narrowly and never used to allow-list
         * attacker-influenceable hosts in production.
         *
         * @param host the discovery host name to allow-list; ignored when {@code null} or blank
         * @return this builder instance
         */
        public WellKnownConfigBuilder allowedEgressHost(String host) {
            if (host != null && !host.isBlank()) {
                allowedEgressHosts.add(host);
            }
            return this;
        }

        /**
         * Sets the well-known endpoint URL as a string.
         *
         * @param wellKnownUrl the well-known endpoint URL string. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if the URL is invalid
         */
        public WellKnownConfigBuilder wellKnownUrl(String wellKnownUrl) {
            httpHandlerBuilder.url(wellKnownUrl);
            return this;
        }

        /**
         * Sets the well-known endpoint URI.
         *
         * @param wellKnownUri the well-known endpoint URI. Must not be null.
         * @return this builder instance
         */
        public WellKnownConfigBuilder wellKnownUri(URI wellKnownUri) {
            httpHandlerBuilder.uri(wellKnownUri);
            return this;
        }

        /**
         * Sets the connection timeout in seconds.
         *
         * @param connectTimeoutSeconds the connection timeout in seconds. Must be positive.
         * @return this builder instance
         * @throws IllegalArgumentException if connectTimeoutSeconds is not positive
         */
        public WellKnownConfigBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            httpHandlerBuilder.connectionTimeoutSeconds(connectTimeoutSeconds);
            return this;
        }

        /**
         * Sets the read timeout in seconds.
         *
         * @param readTimeoutSeconds the read timeout in seconds. Must be positive.
         * @return this builder instance
         * @throws IllegalArgumentException if readTimeoutSeconds is not positive
         */
        public WellKnownConfigBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            httpHandlerBuilder.readTimeoutSeconds(readTimeoutSeconds);
            return this;
        }

        /**
         * Sets the SSL context for HTTPS connections.
         *
         * @param sslContext the SSL context to use
         * @return this builder instance
         */
        public WellKnownConfigBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            this.sslContextSupplied = sslContext != null;
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param tlsVersions the TLS versions configuration
         * @return this builder instance
         */
        public WellKnownConfigBuilder tlsVersions(SecureSSLContextProvider tlsVersions) {
            httpHandlerBuilder.tlsVersions(tlsVersions);
            return this;
        }

        /**
         * Sets the retry configuration for HTTP operations.
         * Defaults to RetryConfig.defaults() if not explicitly set.
         *
         * @param retryConfig the retry configuration to use for HTTP requests
         * @return this builder instance
         */
        public WellKnownConfigBuilder retryConfig(RetryConfig retryConfig) {
            this.retryConfig = retryConfig;
            return this;
        }

        /**
         * Sets the parser configuration for JSON processing.
         *
         * @param parserConfig the parser configuration
         * @return this builder instance
         */
        public WellKnownConfigBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }

        /**
         * Builds a new WellKnownConfig instance.
         *
         * @return a new WellKnownConfig instance
         * @throws IllegalStateException if no well-known URI was configured
         * @throws IllegalArgumentException if the HTTP handler configuration is invalid
         */
        public WellKnownConfig build() {
            // Fail fast BEFORE the try below: that catch rewraps every IllegalArgumentException as
            // "Invalid well-known endpoint configuration", which would present a trust-material conflict
            // as a malformed-endpoint problem. Raising it here keeps the message first-class rather than
            // burying the real cause one level down.
            if (!verifyHostname && sslContextSupplied) {
                throw new IllegalArgumentException(
                        "WellKnownConfigBuilder: verifyHostname(false) cannot be combined with sslContext(...). "
                                + "The hostname relaxation applies only to the default-trust-store context the HTTP handler derives, "
                                + "so a caller-supplied context leaves nothing to relax. Either drop sslContext(...) and supply trust "
                                + "through the JVM default trust store, or keep verifyHostname(true).");
            }
            try {
                httpHandlerBuilder.allowInsecureHttp(allowInsecureHttp);
                httpHandlerBuilder.verifyHostname(verifyHostname);
                HttpHandler httpHandler = httpHandlerBuilder.build();

                // Emit a security warning when the discovery endpoint uses cleartext HTTP,
                // mirroring the JWKS insecure-HTTP warning so insecure endpoints are not silent.
                if ("http".equalsIgnoreCase(httpHandler.getUri().getScheme())) {
                    LOGGER.warn(TransportLogMessages.WARN.INSECURE_HTTP_WELLKNOWN, httpHandler.getUri().toString());
                }

                ParserConfig finalParserConfig = parserConfig != null ? parserConfig : ParserConfig.builder().build();
                EgressPolicy.EgressPolicyBuilder egressPolicyBuilder = EgressPolicy.builder()
                        .allowLoopback(allowLoopbackEgress);
                for (String allowedHost : allowedEgressHosts) {
                    egressPolicyBuilder.allowedHost(allowedHost);
                }
                EgressPolicy egressPolicy = egressPolicyBuilder.build();
                return new WellKnownConfig(httpHandler, retryConfig, finalParserConfig, egressPolicy);
            } catch (IllegalArgumentException | IllegalStateException e) {
                throw new IllegalArgumentException("Invalid well-known endpoint configuration", e);
            }
        }
    }
}