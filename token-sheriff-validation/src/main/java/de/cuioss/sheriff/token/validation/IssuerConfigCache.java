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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;

import static de.cuioss.sheriff.token.validation.JWTValidationLogMessages.ERROR;
import static de.cuioss.sheriff.token.validation.JWTValidationLogMessages.INFO;
import static de.cuioss.sheriff.token.validation.JWTValidationLogMessages.WARN;

/**
 * Thread-safe resolver for issuer configurations with async loading management.
 * <p>
 * This enhanced version triggers async loading for all enabled configs during construction,
 * manages CompletableFuture lifecycle, and only returns configs with LoaderStatus.OK.
 * This eliminates initialization race conditions and provides central coordination,
 * replacing the need for JwksStartupService.
 * <p>
 * The resolver uses a dual-cache approach:
 * <ul>
 *   <li>A ConcurrentHashMap for mutable cache during initialization</li>
 *   <li>An immutable Map for optimal lock-free reads after all configs are loaded</li>
 * </ul>
 * <p>
 * Issuers whose initial JWKS load fails are not lost: on every cache miss the resolver
 * re-checks the loader status of the originally configured issuer, so an issuer that
 * recovers via background refresh becomes resolvable again without a restart.
 * @since 1.0
 */
public class IssuerConfigCache {

    private static final CuiLogger LOGGER = new CuiLogger(IssuerConfigCache.class);

    /**
     * Maximum time to wait for an in-flight initial JWKS load before treating the
     * issuer as unavailable for the current validation attempt.
     */
    private static final long LOADING_WAIT_SECONDS = 5;

    /**
     * Mutable cache used during initialization phase.
     * This ConcurrentHashMap allows thread-safe writes while configs are being resolved.
     */
    private final ConcurrentHashMap<String, IssuerConfig> mutableCache;

    /**
     * Map of issuer identifiers to their loading futures.
     * Used to track and await async loading completion.
     */
    private final ConcurrentHashMap<String, CompletableFuture<LoaderStatus>> loadingFutures;

    /**
     * Immutable cache used after optimization for optimal read performance.
     * This is set once when all configs have been processed and remains immutable thereafter.
     * Null value indicates the cache is still in initialization phase; non-null indicates optimization is complete.
     */
    @SuppressWarnings("java:S3077") // Map.copyOf() creates truly immutable map, safe for concurrent reads after volatile publication
    private volatile @Nullable Map<String, IssuerConfig> immutableCache;

    /**
     * All enabled issuer configurations keyed by issuer identifier.
     * Used as the recovery source when an issuer's initial load failed but its
     * loader later became healthy through background refresh.
     */
    private final Map<String, IssuerConfig> enabledConfigsByIssuer;

    /**
     * Security event counter for tracking validation events.
     */
    private final SecurityEventCounter securityEventCounter;

    /**
     * Creates a new resolver with the given configurations.
     * Triggers async loading for all enabled configurations immediately.
     * Disabled configurations are logged and ignored.
     *
     * @param issuerConfigs        collection of issuer configurations to manage, must not be null
     * @param securityEventCounter counter for security events, must not be null
     */
    IssuerConfigCache(Collection<IssuerConfig> issuerConfigs,
            SecurityEventCounter securityEventCounter) {
        Objects.requireNonNull(issuerConfigs, "issuerConfigs must not be null");
        Objects.requireNonNull(securityEventCounter, "securityEventCounter must not be null");
        this.securityEventCounter = securityEventCounter;
        this.mutableCache = new ConcurrentHashMap<>();
        this.loadingFutures = new ConcurrentHashMap<>();
        this.immutableCache = null; // Will be set after all loading completes

        Map<String, IssuerConfig> enabledConfigs = new ConcurrentHashMap<>();
        // Trigger ALL async loading in constructor
        int totalCount = issuerConfigs.size();
        for (IssuerConfig config : issuerConfigs) {
            if (config.isEnabled()) {
                String issuer = config.getIssuerIdentifier();
                enabledConfigs.put(issuer, config);

                // Single initialization point: trigger async JWKS loading
                CompletableFuture<LoaderStatus> future =
                        config.getJwksLoader().initJWKSLoader(securityEventCounter);

                loadingFutures.put(issuer, future);

                // When loading completes successfully, cache the config
                future.thenAccept(status -> {
                    if (status == LoaderStatus.OK) {
                        mutableCache.put(issuer, config);
                        LOGGER.info(INFO.ISSUER_CONFIG_LOADED, issuer);
                    } else {
                        LOGGER.warn(WARN.ISSUER_CONFIG_LOAD_FAILED, issuer, status);
                    }
                });

                LOGGER.debug("Triggered async loading for issuer: %s", issuer);
            } else {
                LOGGER.info(INFO.ISSUER_CONFIG_SKIPPED, config);
            }
        }
        this.enabledConfigsByIssuer = Map.copyOf(enabledConfigs);

        LOGGER.debug("IssuerConfigCache initialized with %s enabled configurations (%s total)", enabledConfigsByIssuer.size(), totalCount);

        // After all futures are registered, create a combined future to optimize cache when all complete
        if (!loadingFutures.isEmpty()) {
            CompletableFuture.allOf(loadingFutures.values().toArray(new CompletableFuture[0]))
                    .thenRun(this::checkAndOptimize);
        } else {
            // No configs to load, optimize immediately
            checkAndOptimize();
        }
    }

    /**
     * Resolves the issuer configuration for the given issuer identifier.
     * <p>
     * This method implements a four-tier resolution strategy:
     * <ol>
     *   <li><strong>Fast path:</strong> Direct cache lookup (lock-free, constant time)</li>
     *   <li><strong>Loading wait:</strong> Wait for ongoing async loading if in progress</li>
     *   <li><strong>Recovery:</strong> Re-check the configured issuer's loader status — an
     *       issuer whose initial load failed may have recovered via background refresh</li>
     *   <li><strong>Failure:</strong> Throw exception if no healthy config is available</li>
     * </ol>
     * <p>
     * Only returns configurations with LoaderStatus.OK.
     *
     * @param issuer the issuer identifier to resolve, must not be null
     * @return the resolved issuer configuration, never null
     * @throws TokenValidationException if no healthy configuration is found for the issuer
     */
    public IssuerConfig resolveConfig(String issuer) {
        // Fast path - check cache for already loaded configs
        IssuerConfig cached = getCachedConfig(issuer);
        if (cached != null && cached.getJwksLoader().getLoaderStatus() == LoaderStatus.OK) {
            return cached;
        }

        // Check if loading is in progress
        CompletableFuture<LoaderStatus> future = loadingFutures.get(issuer);
        if (future != null) {
            try {
                // Wait for loading to complete (with timeout)
                LoaderStatus status = future.get(LOADING_WAIT_SECONDS, TimeUnit.SECONDS);
                if (status == LoaderStatus.OK) {
                    IssuerConfig loadedConfig = getCachedConfig(issuer);
                    if (loadedConfig != null) {
                        return loadedConfig;
                    }
                }
            } catch (TimeoutException e) {
                LOGGER.warn(WARN.JWKS_LOAD_TIMEOUT, issuer);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn(WARN.JWKS_LOAD_INTERRUPTED, issuer);
            } catch (ExecutionException e) {
                LOGGER.error(e.getCause(), ERROR.JWKS_LOAD_EXECUTION_FAILED, issuer);
            }
        }

        // Recovery path: an issuer whose initial load failed is not in the caches, but its
        // loader keeps retrying via background refresh. If it has become healthy since,
        // re-admit it instead of failing until process restart.
        IssuerConfig candidate = enabledConfigsByIssuer.get(issuer);
        if (candidate != null && candidate.getJwksLoader() != null
                && candidate.getJwksLoader().getLoaderStatus() == LoaderStatus.OK) {
            mutableCache.put(issuer, candidate);
            LOGGER.info(INFO.ISSUER_CONFIG_LOADED, issuer);
            return candidate;
        }

        // Not found or not healthy
        throw issuerNotFound(issuer);
    }

    /**
     * Gets a cached configuration from either immutable or mutable cache.
     *
     * @param issuer the issuer identifier to look up
     * @return the cached config if found, null otherwise
     */
    private @Nullable IssuerConfig getCachedConfig(String issuer) {
        // Try immutable cache first if available (lock-free)
        if (immutableCache != null) {
            IssuerConfig cached = immutableCache.get(issuer);
            if (cached != null) {
                LOGGER.debug("Using cached issuer config from immutable cache for: %s", issuer);
                return cached;
            }
        }

        // Fallback to mutable cache
        IssuerConfig cached = mutableCache.get(issuer);
        if (cached != null) {
            LOGGER.debug("Using cached issuer config from mutable cache for: %s", issuer);
            return cached;
        }

        return null;
    }

    /**
     * Checks if all loading has completed and optimizes the cache if needed.
     * <p>
     * Creates an immutable copy of the mutable cache for optimal read performance.
     * The immutable cache is set atomically via volatile write, ensuring thread-safe
     * publication without requiring additional synchronization for reads.
     */
    private void checkAndOptimize() {
        synchronized (this) {
            if (immutableCache == null) {
                // Check if all futures are complete
                boolean allComplete = loadingFutures.values().stream()
                        .allMatch(CompletableFuture::isDone);

                if (allComplete) {
                    // Create immutable copy from mutable cache
                    Map<String, IssuerConfig> optimizedCache = Map.copyOf(mutableCache);
                    LOGGER.debug("Created immutable cache for read-only access with %s entries", optimizedCache.size());

                    // Set immutable cache via volatile write for thread-safe publication
                    immutableCache = optimizedCache;
                    LOGGER.debug("Issuer config cache optimized for read-only access");

                    // Clear loading futures as they're no longer needed
                    loadingFutures.clear();
                }
            }
        }
    }

    /**
     * Creates the exception for the case where no issuer configuration is found,
     * logging a warning and incrementing the security event counter.
     *
     * @param issuer the issuer identifier that wasn't found
     * @return the exception to throw, with NO_ISSUER_CONFIG event type
     */
    private TokenValidationException issuerNotFound(String issuer) {
        LOGGER.warn(WARN.NO_ISSUER_CONFIG, issuer);
        securityEventCounter.increment(SecurityEventCounter.EventType.NO_ISSUER_CONFIG);
        return new TokenValidationException(
                SecurityEventCounter.EventType.NO_ISSUER_CONFIG,
                "No healthy issuer configuration found for issuer: " + issuer
        );
    }
}