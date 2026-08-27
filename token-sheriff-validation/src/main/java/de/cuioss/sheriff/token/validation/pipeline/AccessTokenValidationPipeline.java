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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.IssuerConfigCache;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCache;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.dpop.DpopProofValidator;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.metrics.MeasurementType;
import de.cuioss.sheriff.token.validation.metrics.MetricsTicker;
import de.cuioss.sheriff.token.validation.metrics.MetricsTickerFactory;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenClaimValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenValidationRule;
import de.cuioss.tools.logging.CuiLogger;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Pipeline for validating access tokens with caching support.
 * <p>
 * Access tokens are the most frequently validated token type and benefit from
 * aggressive caching and early cache checks. This pipeline performs an early
 * cache lookup after parsing and issuer extraction, but before expensive
 * cryptographic signature validation.
 * <p>
 * <strong>Validation Steps:</strong>
 * <ol>
 *   <li>Parse token into header and payload (metrics: TOKEN_PARSING)</li>
 *   <li>Extract and validate issuer claim (metrics: ISSUER_EXTRACTION)</li>
 *   <li><strong>CHECK CACHE - EARLY</strong> (metrics: CACHE_LOOKUP) ← Issue #131 optimization</li>
 *   <li>If cache miss, resolve issuer configuration (metrics: ISSUER_CONFIG_RESOLUTION)</li>
 *   <li>If cache miss, validate JWT header (metrics: HEADER_VALIDATION)</li>
 *   <li>If cache miss, validate JWT signature (metrics: SIGNATURE_VALIDATION) ← Most expensive</li>
 *   <li>If cache miss, build typed AccessTokenContent object (metrics: TOKEN_BUILDING)</li>
 *   <li>If cache miss, validate token claims (metrics: CLAIMS_VALIDATION)</li>
 *   <li>If cache miss, store in cache (metrics: CACHE_STORE)</li>
 * </ol>
 * <p>
 * <strong>Note:</strong> TokenStringValidator has already validated that the token
 * is non-null, non-blank, and within size limits before this pipeline is called.
 * <p>
 * <strong>Full Metrics Instrumentation:</strong> Access token validation uses
 * {@code TokenValidatorMonitor} to record detailed performance metrics for each
 * validation step, enabling fine-grained performance analysis.
 * <p>
 * <strong>Critical Optimization:</strong> The cache check happens at step 3, after
 * minimal parsing but before expensive cryptographic operations. This addresses
 * <a href="https://github.com/cuioss/TokenSheriff/issues/131">issue #131</a> by maximizing
 * cache hit performance.
 * <p>
 * This class is thread-safe after construction. All validators are pre-created
 * and cached in immutable maps for optimal performance.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class AccessTokenValidationPipeline {

    private static final CuiLogger LOGGER = new CuiLogger(AccessTokenValidationPipeline.class);

    private final NonValidatingJwtParser jwtParser;
    private final IssuerConfigCache issuerConfigCache;
    private final Map<String, TokenSignatureValidator> signatureValidators;
    private final Map<String, TokenBuilder> tokenBuilders;
    private final Map<String, TokenClaimValidator> claimValidators;
    private final Map<String, TokenHeaderValidator> headerValidators;
    private final Map<String, DpopProofValidator> dpopValidators;
    private final List<TokenValidationRule> customValidationRules;
    private final AccessTokenCache cache;
    private final SecurityEventCounter securityEventCounter;
    private final TokenValidatorMonitor performanceMonitor;

    /**
     * Creates a new AccessTokenValidationPipeline.
     *
     * @param jwtParser the JWT parser for decoding tokens
     * @param issuerConfigCache the resolver for issuer configurations
     * @param signatureValidators pre-created signature validators keyed by issuer
     * @param tokenBuilders pre-created token builders keyed by issuer
     * @param claimValidators pre-created claim validators keyed by issuer
     * @param headerValidators pre-created header validators keyed by issuer
     * @param dpopValidators pre-created DPoP validators keyed by issuer (may be empty)
     * @param customValidationRules custom validation rules executed after built-in validation
     * @param cacheConfig the cache configuration for access token caching
     * @param securityEventCounter the security event counter for tracking operations
     * @param performanceMonitor the monitor for recording performance metrics
     * @param maxClockSkewSeconds the maximum clock skew tolerance across all issuers (for cache expiration)
     */
    @SuppressWarnings("java:S107") // Many dependencies are required
    public AccessTokenValidationPipeline(NonValidatingJwtParser jwtParser,
            IssuerConfigCache issuerConfigCache,
            Map<String, TokenSignatureValidator> signatureValidators,
            Map<String, TokenBuilder> tokenBuilders,
            Map<String, TokenClaimValidator> claimValidators,
            Map<String, TokenHeaderValidator> headerValidators,
            Map<String, DpopProofValidator> dpopValidators,
            List<TokenValidationRule> customValidationRules,
            AccessTokenCacheConfig cacheConfig,
            SecurityEventCounter securityEventCounter,
            TokenValidatorMonitor performanceMonitor,
            int maxClockSkewSeconds) {
        this.jwtParser = jwtParser;
        this.issuerConfigCache = issuerConfigCache;
        this.signatureValidators = signatureValidators;
        this.tokenBuilders = tokenBuilders;
        this.claimValidators = claimValidators;
        this.headerValidators = headerValidators;
        this.dpopValidators = dpopValidators;
        this.customValidationRules = List.copyOf(customValidationRules);
        this.cache = new AccessTokenCache(cacheConfig, securityEventCounter, maxClockSkewSeconds);
        this.securityEventCounter = securityEventCounter;
        this.performanceMonitor = performanceMonitor;
    }

    /**
     * Validates and returns an access token with caching support.
     * <p>
     * This method performs early cache checks before expensive signature validation
     * to optimize performance for repeated token validation (addresses issue #131).
     * <p>
     * If the token is found in cache and is still valid, it is returned immediately
     * without performing expensive cryptographic operations.
     *
     * @param request the access token validation request (token string guaranteed non-null, non-blank, within size limits)
     * @return the validated access token content
     * @throws TokenValidationException if any validation step fails
     */
    public AccessTokenContent validate(AccessTokenRequest request) {
        LOGGER.debug("Validating access token");
        String tokenString = request.tokenString();

        // TokenStringValidator has already checked: null, blank, size

        // Create current time once for cache and validation context consistency
        OffsetDateTime now = OffsetDateTime.now();

        // 1. CHECK CACHE FIRST - before any expensive parsing
        Optional<AccessTokenContent> cached = cache.get(tokenString, performanceMonitor, now);
        if (cached.isPresent()) {
            LOGGER.debug("Access token retrieved from cache");
            AccessTokenContent cachedToken = cached.get();
            // Still validate DPoP proof even for cached tokens (proofs must be fresh per request)
            runDpopValidation(request, cachedToken.getIssuer(), tokenString);
            // Re-run custom validation rules on every cache hit (M5): a stateful custom rule
            // (revocation, dynamic policy, rate limit) must be honored on each request and must not
            // be bypassed by the cache. Without this, a token that passed once would be served
            // indefinitely even after a rule flips to reject it.
            if (!customValidationRules.isEmpty()) {
                IssuerConfig cachedIssuerConfig = issuerConfigCache.resolveConfig(cachedToken.getIssuer());
                ValidationContext cacheHitContext = new ValidationContext(now,
                        cachedIssuerConfig.getClockSkewSeconds(), cachedIssuerConfig.getMaxTokenAgeSeconds());
                for (TokenValidationRule rule : customValidationRules) {
                    rule.validate(cachedToken, cacheHitContext);
                }
            }
            return cachedToken;
        }

        // 2. Parse token (with TOKEN_PARSING metrics)
        MetricsTicker parsingTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.TOKEN_PARSING, performanceMonitor);
        DecodedJwt decodedJwt;
        try {
            decodedJwt = jwtParser.decode(tokenString);
        } finally {
            parsingTicker.stopAndRecord();
        }

        // 3. Extract issuer (with ISSUER_EXTRACTION metrics)
        MetricsTicker extractionTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.ISSUER_EXTRACTION, performanceMonitor);
        String issuer;
        try {
            issuer = decodedJwt.getIssuer().orElseThrow(() -> {
                LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "iss");
                securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
                return new TokenValidationException(
                        SecurityEventCounter.EventType.MISSING_CLAIM,
                        "Missing required issuer (iss) claim in token"
                );
            });
        } finally {
            extractionTicker.stopAndRecord();
        }

        // 4. Resolve issuer config (with ISSUER_CONFIG_RESOLUTION metrics)
        MetricsTicker configTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.ISSUER_CONFIG_RESOLUTION, performanceMonitor);
        IssuerConfig issuerConfig;
        try {
            issuerConfig = issuerConfigCache.resolveConfig(issuer);
        } finally {
            configTicker.stopAndRecord();
        }

        // 5. Validate header (with HEADER_VALIDATION metrics)
        MetricsTicker headerTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.HEADER_VALIDATION, performanceMonitor);
        try {
            ValidatorLookup.getOrThrow(headerValidators, issuerConfig.getIssuerIdentifier(), "header validator")
                    .validate(decodedJwt, request);
        } finally {
            headerTicker.stopAndRecord();
        }

        // 6. Validate signature (with SIGNATURE_VALIDATION metrics) ← MOST expensive operation
        MetricsTicker signatureTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.SIGNATURE_VALIDATION, performanceMonitor);
        try {
            ValidatorLookup.getOrThrow(signatureValidators, issuerConfig.getIssuerIdentifier(), "signature validator")
                    .validateSignature(decodedJwt);
        } finally {
            signatureTicker.stopAndRecord();
        }

        // 7. Build token (with TOKEN_BUILDING metrics)
        MetricsTicker buildingTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.TOKEN_BUILDING, performanceMonitor);
        AccessTokenContent accessToken;
        try {
            TokenBuilder tokenBuilder = ValidatorLookup.getOrThrow(tokenBuilders, issuerConfig.getIssuerIdentifier(), "token builder");
            Optional<AccessTokenContent> tokenOpt = tokenBuilder.createAccessToken(decodedJwt);
            if (tokenOpt.isEmpty()) {
                LOGGER.debug("Access token building failed");
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.MISSING_CLAIM,
                        "Failed to build access token from decoded JWT"
                );
            }
            accessToken = tokenOpt.get();
        } finally {
            buildingTicker.stopAndRecord();
        }

        // 8. Validate claims (with CLAIMS_VALIDATION metrics)
        // Reuse the 'now' timestamp from line 162 for consistency across cache check and claims validation
        // Use per-issuer clock skew and max token age from IssuerConfig
        ValidationContext context = new ValidationContext(now,
                issuerConfig.getClockSkewSeconds(),
                issuerConfig.getMaxTokenAgeSeconds());
        MetricsTicker claimsTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.CLAIMS_VALIDATION, performanceMonitor);
        AccessTokenContent validatedToken;
        try {
            validatedToken = (AccessTokenContent) ValidatorLookup.getOrThrow(claimValidators, issuerConfig.getIssuerIdentifier(), "claim validator")
                    .validate(accessToken, context);
        } finally {
            claimsTicker.stopAndRecord();
        }

        // 8.5 Validate DPoP proof (after claims validation, before cache store)
        runDpopValidation(request, decodedJwt, issuerConfig.getIssuerIdentifier(), tokenString);

        // 8.6 Run custom validation rules (after all built-in validation, before cache store)
        for (TokenValidationRule rule : customValidationRules) {
            rule.validate(validatedToken, context);
        }

        LOGGER.debug("Token successfully validated");

        // 9. Store in cache for future lookups
        cache.put(tokenString, validatedToken, performanceMonitor);

        return validatedToken;
    }

    /**
     * Runs DPoP validation for a full (non-cached) validation flow.
     */
    private void runDpopValidation(AccessTokenRequest request, DecodedJwt decodedJwt,
            String issuerIdentifier, String tokenString) {
        DpopProofValidator dpopValidator = dpopValidators.get(issuerIdentifier);
        if (dpopValidator != null) {
            dpopValidator.validate(request, decodedJwt, tokenString);
        }
    }

    /**
     * Runs DPoP validation for cached tokens by re-parsing the token minimally.
     * For cached tokens, we still need to validate the DPoP proof since proofs must be fresh.
     */
    private void runDpopValidation(AccessTokenRequest request, String issuerIdentifier, String tokenString) {
        DpopProofValidator dpopValidator = dpopValidators.get(issuerIdentifier);
        if (dpopValidator != null) {
            // Re-decode the token to get access to cnf.jkt for DPoP validation
            DecodedJwt decodedJwt = jwtParser.decodeQuietly(tokenString);
            dpopValidator.validate(request, decodedJwt, tokenString);
        }
    }

    /**
     * Shuts down the internal cache eviction executor. Must be called when the pipeline
     * is no longer needed to prevent daemon thread leaks.
     */
    public void shutdown() {
        cache.shutdown();
    }
}
