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

import de.cuioss.http.client.adapter.ETagAwareHttpAdapter;
import de.cuioss.http.client.adapter.HttpAdapter;
import de.cuioss.http.client.adapter.ResilientHttpAdapter;
import de.cuioss.http.client.result.HttpResult;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HTTP-based implementation for resolving OpenID Connect well-known configuration endpoints.
 * <p>
 * This class provides a thin wrapper around {@link HttpAdapter} for loading and
 * parsing well-known OIDC discovery documents. It handles HTTP operations, caching via ETag,
 * and provides convenient access to discovered endpoints.
 * <p>
 * The resolver loads the well-known configuration once and caches the result for
 * subsequent endpoint lookups. It provides methods to access common OIDC endpoints
 * like JWKS URI, issuer, authorization endpoint, etc.
 * <p>
 * <strong>Thread Safety:</strong> a cached success is served through a lock-free {@code AtomicReference}
 * fast path, while the side-effecting (re)load — the SSRF egress check, the blocking HTTP fetch, and the
 * status transitions — runs under a single-flight monitor so only one thread loads per refresh and racing
 * callers reuse the winning result. The load is deliberately kept out of any {@code updateAndGet} callback,
 * whose function may re-run under CAS contention.
 * <p>
 * <strong>Caching semantics (M2):</strong> only <em>successful</em> discovery results are cached,
 * and each cached success carries a bounded time-to-live ({@link #DISCOVERY_SUCCESS_TTL}). Once the
 * TTL elapses the next lookup revalidates against the endpoint, so discovery metadata cannot be
 * pinned indefinitely. A <em>failed</em> discovery is never cached — it is retried on the next call
 * rather than being pinned as a permanent negative result.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class HttpWellKnownResolver implements LoadingStatusProvider {

    private static final CuiLogger LOGGER = new CuiLogger(HttpWellKnownResolver.class);

    /**
     * Bounded time-to-live for a cached <em>successful</em> discovery result before it is
     * revalidated (M2). Keeps a stale discovery document from being served indefinitely while
     * still avoiding a network round-trip on every lookup.
     */
    private static final Duration DISCOVERY_SUCCESS_TTL = Duration.ofMinutes(15);

    private final HttpAdapter<WellKnownResult> wellKnownAdapter;
    private final long successTtlNanos;

    /**
     * SSRF egress guard applied to the discovery endpoint immediately before it is fetched (C1).
     * Resolving the discovery host fresh at each fetch — rather than trusting an earlier
     * resolution — also closes the DNS-rebinding window for the well-known document itself,
     * mirroring the guard {@code HttpJwksLoader} applies to the advertised {@code jwks_uri}.
     */
    private final EgressPolicy egressPolicy;

    /**
     * The discovery endpoint URI the egress guard resolves and validates before every fetch.
     */
    private final URI discoveryUri;

    private final AtomicReference<CachedDiscovery> cachedResult = new AtomicReference<>();
    private final AtomicReference<LoaderStatus> status = new AtomicReference<>(LoaderStatus.UNDEFINED);

    /**
     * Holds a cached successful discovery result together with the {@link System#nanoTime()}
     * instant at which it expires and must be revalidated.
     *
     * @param result       the successful discovery result
     * @param expiresAtNanos the {@link System#nanoTime()} deadline after which {@code result} is stale
     */
    private record CachedDiscovery(HttpResult<WellKnownResult> result, long expiresAtNanos) {

        boolean isFresh() {
            return System.nanoTime() - expiresAtNanos < 0;
        }
    }

    /**
     * Creates a new HttpWellKnownResolver with the specified configuration.
     * <p>
     * The resolver uses a composition of adapters:
     * <ul>
     * <li>Base: {@link ETagAwareHttpAdapter} for bandwidth optimization via ETag caching</li>
     * <li>Decorator: {@link ResilientHttpAdapter} for retry behavior</li>
     * </ul>
     *
     * @param config the well-known configuration containing HTTP handler and parser settings
     * @param securityEventCounter the shared security event counter for tracking violations
     */
    public HttpWellKnownResolver(WellKnownConfig config, SecurityEventCounter securityEventCounter) {
        this(config, securityEventCounter, DISCOVERY_SUCCESS_TTL);
    }

    /**
     * Creates a new HttpWellKnownResolver with an explicit success TTL.
     * <p>
     * Package-private overload used by tests to exercise the bounded-TTL revalidation path (M2)
     * deterministically without waiting out the production {@link #DISCOVERY_SUCCESS_TTL}.
     *
     * @param config the well-known configuration containing HTTP handler and parser settings
     * @param securityEventCounter the shared security event counter for tracking violations
     * @param successTtl the bounded time-to-live for a cached successful discovery result
     */
    HttpWellKnownResolver(WellKnownConfig config, SecurityEventCounter securityEventCounter, Duration successTtl) {
        var converter = new WellKnownConfigurationConverter(
                config.getParserConfig().getDslJson(),
                securityEventCounter,
                config.getParserConfig().getMaxPayloadSize());

        // Create base adapter with ETag caching
        HttpAdapter<WellKnownResult> baseAdapter = ETagAwareHttpAdapter.<WellKnownResult>builder()
                .httpHandler(config.getHttpHandler())
                .responseConverter(converter)
                .build();

        // Wrap with retry behavior
        this.wellKnownAdapter = ResilientHttpAdapter.wrap(baseAdapter, config.getRetryConfig());
        this.successTtlNanos = successTtl.toNanos();
        this.egressPolicy = config.getEgressPolicy();
        this.discoveryUri = config.getHttpHandler().getUri();

        LOGGER.debug("Created HttpWellKnownResolver for well-known endpoint discovery");
    }

    /**
     * Ensures the well-known configuration is loaded and cached using thread-safe lazy initialization.
     * <p>
     * A lock-free fast path serves a cached success while it is still within its bounded TTL (M2).
     * When the cache is empty or the cached success has expired, the actual load runs inside
     * {@link #loadDiscovery()} under this instance's monitor, so the SSRF egress check, the blocking
     * HTTP fetch, and the {@link #status} transitions each execute <em>at most once</em> per refresh.
     * The side-effecting load is deliberately kept out of any {@code AtomicReference} update callback:
     * {@link AtomicReference#updateAndGet} may re-run its function under CAS contention, which would
     * let the egress check and HTTP load fire more than once and leave {@code status} out of sync with
     * the winning cache entry.
     *
     * @return Optional containing the WellKnownResult if available and valid, empty otherwise
     */
    private Optional<WellKnownResult> ensureLoaded() {
        // Fast path: reuse a cached success while it is still within its bounded TTL (M2) — no lock.
        CachedDiscovery current = cachedResult.get();
        if (current != null && current.isFresh()) {
            return current.result().getContent();
        }
        return loadDiscovery();
    }

    /**
     * Performs the single-flight discovery load. The {@code synchronized} monitor is the single-flight
     * gate: only one thread runs the SSRF egress check and the blocking HTTP fetch at a time, while
     * racing callers block and then reuse whichever result the winning thread cached. A failed load is
     * never cached (M2), so failures remain retryable on the next call rather than being pinned as a
     * permanent negative result.
     *
     * @return Optional containing the WellKnownResult if the (re)load succeeded, empty otherwise
     */
    private synchronized Optional<WellKnownResult> loadDiscovery() {
        // Re-check under the lock: a racing thread may have completed the (re)load while we waited.
        CachedDiscovery current = cachedResult.get();
        if (current != null && current.isFresh()) {
            return current.result().getContent();
        }
        // No cache yet, or an expired success: (re)load. A previously failed load was never cached
        // (see below), so a failure never reaches this branch as a pinned negative result.
        status.set(LoaderStatus.LOADING);
        // SSRF egress guard (C1): resolve the discovery endpoint and reject it if it lands on an
        // internal/loopback/link-local/metadata address BEFORE any fetch is issued. Because each
        // (re)load re-runs this fresh resolution, a DNS rebind that flips the discovery host into a
        // blocked range after an earlier fetch is caught on the next revalidation, not trusted.
        try {
            egressPolicy.check(discoveryUri);
        } catch (TransportException e) {
            LOGGER.warn(e, TransportLogMessages.WARN.SSRF_EGRESS_BLOCKED_DISCOVERY, e.getMessage());
            // Do not cache failures (M2): clear any expired entry so the next call retries discovery.
            cachedResult.set(null);
            status.set(LoaderStatus.ERROR);
            return Optional.empty();
        }
        HttpResult<WellKnownResult> loaded = wellKnownAdapter.getBlocking();
        if (loaded.isSuccess()) {
            // Publish the cache entry BEFORE flipping status to OK so a fast-path reader that observes
            // OK also observes the fresh entry.
            cachedResult.set(new CachedDiscovery(loaded, System.nanoTime() + successTtlNanos));
            status.set(LoaderStatus.OK);
            return loaded.getContent();
        }
        // Do not cache failures (M2): clearing the cache lets the next call retry discovery instead of
        // pinning a permanent negative result.
        cachedResult.set(null);
        status.set(LoaderStatus.ERROR);
        return Optional.empty();
    }

    /**
     * Gets the JWKS URI from the well-known configuration.
     *
     * @return Optional containing the JWKS URI if available, empty otherwise
     */
    public Optional<String> getJwksUri() {
        return ensureLoaded().flatMap(WellKnownResult::getJwksUri);
    }

    /**
     * Gets the issuer from the well-known configuration.
     *
     * @return Optional containing the issuer if available, empty otherwise
     */
    public Optional<String> getIssuer() {
        return ensureLoaded().flatMap(WellKnownResult::getIssuer);
    }

    /**
     * Gets the complete well-known configuration result.
     *
     * @return Optional containing the WellKnownResult if available, empty otherwise
     */
    Optional<WellKnownResult> getWellKnownResult() {
        return ensureLoaded();
    }

    /**
     * Checks the health status of the well-known resolver.
     * <p>
     * Returns the current loading status tracked through the {@link #status} field.
     *
     * @return the current LoaderStatus indicating health state
     */
    @Override
    public LoaderStatus getLoaderStatus() {
        return status.get();
    }
}