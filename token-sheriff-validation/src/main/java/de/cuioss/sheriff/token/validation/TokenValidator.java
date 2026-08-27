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
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.RefreshTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.UnvalidatedRefreshToken;
import de.cuioss.sheriff.token.validation.dpop.DpopProofValidator;
import de.cuioss.sheriff.token.validation.dpop.DpopReplayProtection;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.sheriff.token.validation.metrics.*;
import de.cuioss.sheriff.token.validation.pipeline.*;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenClaimValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenStringValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenValidationRule;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Main entry point for creating and validating JWT tokens.
 * <p>
 * This class provides methods for creating different types of tokens from
 * JWT strings, handling the validation and parsing process.
 * <p>
 * The validator uses a pipeline approach to validate tokens:
 * <ol>
 *   <li>Basic format validation</li>
 *   <li>Issuer validation</li>
 *   <li>Header validation</li>
 *   <li>Signature validation</li>
 *   <li>Token building</li>
 *   <li>Claim validation</li>
 * </ol>
 * <p>
 * This class is thread-safe after construction.
 * All validation methods can be called concurrently from multiple threads.
 * <p>
 * <strong>Design Note:</strong> This class intentionally implements the facade/factory pattern,
 * orchestrating the creation and wiring of all JWT validation components. The higher dependency
 * count is a natural consequence of this design pattern and is acceptable for a public API
 * entry point that encapsulates significant complexity.
 * <p>
 * Usage example:
 * <pre>
 * // Configure HTTP-based JWKS loading
 * HttpJwksLoaderConfig httpConfig = HttpJwksLoaderConfig.builder()
 *     .jwksUrl("https://example.com/.well-known/jwks.json")
 *     .refreshIntervalSeconds(60)
 *     .build();
 *
 * // Create an issuer configuration
 * IssuerConfig issuerConfig = IssuerConfig.builder()
 *     .issuerIdentifier("https://example.com")
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(httpConfig)
 *     .build(); // Validation happens automatically
 *
 * // Create the token validator with custom metrics and cache configuration
 * TokenValidatorMonitorConfig metricsConfig = TokenValidatorMonitorConfig.builder()
 *     .windowSize(200)
 *     .measurementType(MeasurementType.SIGNATURE_VALIDATION)
 *     .measurementType(MeasurementType.COMPLETE_VALIDATION)
 *     .build();
 *
 * // Configure access token caching
 * AccessTokenCacheConfig cacheConfig = AccessTokenCacheConfig.builder()
 *     .maxSize(500)  // Set to 0 to disable caching
 *     .evictionIntervalSeconds(300L)
 *     .build();
 *
 * // The validator creates a SecurityEventCounter internally and passes it to all components
 * TokenValidator tokenValidator = TokenValidator.builder()
 *     .parserConfig(ParserConfig.builder().build())
 *     .issuerConfig(issuerConfig)
 *     .monitorConfig(metricsConfig)  // Optional: null means no types monitored
 *     .cacheConfig(cacheConfig)      // Optional: null means default caching enabled
 *     .build();
 *
 * // Parse an access token
 * AccessTokenContent accessToken = tokenValidator.createAccessToken(AccessTokenRequest.of(tokenString));
 *
 * // Parse an ID token
 * IdTokenContent idToken = tokenValidator.createIdToken(IdTokenRequest.of(tokenString));
 *
 * // Parse a refresh token
 * UnvalidatedRefreshToken refreshToken = tokenValidator.createRefreshToken(RefreshTokenRequest.of(tokenString));
 *
 * // Access the security event counter for monitoring
 * SecurityEventCounter securityEventCounter = tokenValidator.getSecurityEventCounter();
 *
 * // Access the performance monitor for detailed pipeline metrics
 * TokenValidatorMonitor performanceMonitor = tokenValidator.getPerformanceMonitor();
 * Optional&lt;StripedRingBufferStatistics&gt; metrics =
 *         performanceMonitor.getValidationMetrics(MeasurementType.SIGNATURE_VALIDATION);
 * Optional&lt;Duration&gt; p50SignatureTime = metrics.map(StripedRingBufferStatistics::p50);
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1">VALIDATION-1: Token Parsing and Validation</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-2">VALIDATION-2: Token Representation</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-3">VALIDATION-3: Multi-Issuer Support</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#_tokenvalidator">Technical Components Specification</a>
 *
 * @since 1.0
 */
@SuppressWarnings({"JavadocLinkAsPlainText", "java:S6539"}) // java:S6539: Intentional facade pattern - high coupling is by design
public class TokenValidator implements Closeable {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidator.class);

    /**
     * Counter for security events that occur during token processing.
     * This counter is thread-safe and can be accessed from outside to monitor security events.
     */
    @Getter
    private final SecurityEventCounter securityEventCounter;

    /**
     * Monitor for performance metrics of JWT validation pipeline steps.
     * This monitor is thread-safe and provides detailed timing measurements for each validation step.
     */
    @Getter
    private final TokenValidatorMonitor performanceMonitor;

    /**
     * Validator for pre-pipeline token string validation (null, blank, size checks).
     * This validator runs before any pipeline processing to fail fast on invalid inputs.
     */
    private final TokenStringValidator tokenStringValidator;

    /**
     * Pipeline for validating access tokens with caching support.
     * Handles full validation including early cache checks before expensive operations.
     */
    private final AccessTokenValidationPipeline accessTokenPipeline;

    /**
     * Pipeline for validating ID tokens without caching.
     * Handles full validation for ID tokens used during authentication flows.
     */
    private final IdTokenValidationPipeline idTokenPipeline;

    /**
     * Pipeline for validating refresh tokens with minimal validation.
     * Handles opaque or lightly validated refresh tokens.
     */
    private final RefreshTokenValidationPipeline refreshTokenPipeline;

    /**
     * Shared DPoP replay protection instance, or null if no issuer has DPoP enabled.
     * Stored for lifecycle management ({@link #close()}).
     */
    @Nullable
    private final DpopReplayProtection dpopReplayProtection;


    /**
     * Private constructor used by builder.
     */
    @Builder
    private TokenValidator(
            @Nullable ParserConfig parserConfig,
            @Singular List<IssuerConfig> issuerConfigs,
            @Singular List<TokenValidationRule> tokenValidationRules,
            @Nullable TokenValidatorMonitorConfig monitorConfig,
            @Nullable AccessTokenCacheConfig cacheConfig,
            @Nullable JweDecryptionConfig jweDecryptionConfig) {

        if (issuerConfigs.isEmpty()) {
            throw new IllegalArgumentException("At least one issuer configuration must be provided");
        }
        if (issuerConfigs.contains(null)) {
            throw new IllegalArgumentException("Issuer configurations must not contain null elements");
        }

        // Disabled configs skip build-time validation and have no JwksLoader — they must not
        // participate in validator construction. IssuerConfigCache performs the same filtering
        // (and logs the skipped configs).
        List<IssuerConfig> enabledIssuerConfigs = issuerConfigs.stream()
                .filter(IssuerConfig::isEnabled)
                .toList();
        if (enabledIssuerConfigs.isEmpty()) {
            throw new IllegalArgumentException("At least one enabled issuer configuration must be provided");
        }

        // Use default ParserConfig if not provided
        if (parserConfig == null) {
            parserConfig = ParserConfig.builder().build();
        }

        LOGGER.debug("Initialize token validator with %s and %s issuer configurations", parserConfig, issuerConfigs.size());

        // Always create new instances internally
        this.securityEventCounter = new SecurityEventCounter();

        // Create monitor based on configuration
        if (monitorConfig != null) {
            this.performanceMonitor = monitorConfig.createMonitor();
        } else {
            // Default: disabled monitoring
            this.performanceMonitor = TokenValidatorMonitorConfig.disabled().createMonitor();
        }

        // Construction-time dependencies - used only to build pipelines, not stored as fields
        NonValidatingJwtParser jwtParser = NonValidatingJwtParser.builder()
                .config(parserConfig)
                .securityEventCounter(this.securityEventCounter)
                .jweDecryptionConfig(jweDecryptionConfig)
                .build();

        // Let the IssuerConfigCache handle all issuer config processing
        IssuerConfigCache issuerConfigCache = new IssuerConfigCache(issuerConfigs, this.securityEventCounter);

        // Initialize immutable map of TokenSignatureValidator instances for each issuer
        // This eliminates the performance bottleneck of creating new instances on every validation
        Map<String, TokenSignatureValidator> signatureValidatorsMap = new HashMap<>();
        Map<String, SignatureTemplateManager> signatureTemplateManagers = new HashMap<>();
        Map<String, TokenBuilder> tokenBuildersMap = new HashMap<>();
        Map<String, TokenClaimValidator> claimValidatorsMap = new HashMap<>();
        Map<String, TokenHeaderValidator> headerValidatorsMap = new HashMap<>();

        for (IssuerConfig issuerConfig : enabledIssuerConfigs) {
            String issuerIdentifier = issuerConfig.getIssuerIdentifier();

            // Create one shared SignatureTemplateManager per issuer (reused by signature + DPoP validators)
            SignatureTemplateManager signatureTemplateManager = new SignatureTemplateManager(issuerConfig.getAlgorithmPreferences());
            signatureTemplateManagers.put(issuerIdentifier, signatureTemplateManager);

            // Initialize signature validator
            TokenSignatureValidator signatureValidator = new TokenSignatureValidator(
                    issuerConfig.getJwksLoader(),
                    this.securityEventCounter,
                    signatureTemplateManager
            );
            signatureValidatorsMap.put(issuerIdentifier, signatureValidator);
            LOGGER.debug("Pre-created TokenSignatureValidator for issuer: %s", issuerIdentifier);

            // Initialize token builder
            TokenBuilder tokenBuilder = new TokenBuilder(issuerConfig);
            tokenBuildersMap.put(issuerIdentifier, tokenBuilder);
            LOGGER.debug("Pre-created TokenBuilder for issuer: %s", issuerIdentifier);

            // Initialize claim validator
            TokenClaimValidator claimValidator = new TokenClaimValidator(issuerConfig, this.securityEventCounter);
            claimValidatorsMap.put(issuerIdentifier, claimValidator);
            LOGGER.debug("Pre-created TokenClaimValidator for issuer: %s", issuerIdentifier);

            // Initialize header validator
            TokenHeaderValidator headerValidator = new TokenHeaderValidator(issuerConfig, this.securityEventCounter);
            headerValidatorsMap.put(issuerIdentifier, headerValidator);
            LOGGER.debug("Pre-created TokenHeaderValidator for issuer: %s", issuerIdentifier);
        }

        Map<String, TokenSignatureValidator> signatureValidators = Map.copyOf(signatureValidatorsMap);
        Map<String, TokenBuilder> tokenBuilders = Map.copyOf(tokenBuildersMap);
        Map<String, TokenClaimValidator> claimValidators = Map.copyOf(claimValidatorsMap);
        Map<String, TokenHeaderValidator> headerValidators = Map.copyOf(headerValidatorsMap);

        // Initialize DPoP validators for issuers that have DPoP configured
        // Shared replay protection across all issuers (jti must be globally unique per RFC 9449)
        // Use max TTL and max cache size across all DPoP-enabled issuers for consistent behavior
        Map<String, DpopProofValidator> dpopValidatorsMap = new HashMap<>();
        long maxNonceCacheTtl = 0;
        int maxNonceCacheSize = 0;
        for (IssuerConfig issuerConfig : enabledIssuerConfigs) {
            if (issuerConfig.getDpopConfig() != null) {
                maxNonceCacheTtl = Math.max(maxNonceCacheTtl, issuerConfig.getDpopConfig().getNonceCacheTtlSeconds());
                maxNonceCacheSize = Math.max(maxNonceCacheSize, issuerConfig.getDpopConfig().getNonceCacheSize());
            }
        }
        this.dpopReplayProtection = maxNonceCacheSize > 0
                ? new DpopReplayProtection(maxNonceCacheTtl, maxNonceCacheSize)
                : null;
        for (IssuerConfig issuerConfig : enabledIssuerConfigs) {
            if (issuerConfig.getDpopConfig() != null) {
                DpopProofValidator dpopValidator = new DpopProofValidator(
                        issuerConfig, this.securityEventCounter, this.dpopReplayProtection,
                        signatureTemplateManagers.get(issuerConfig.getIssuerIdentifier()),
                        parserConfig, parserConfig.getDslJson());
                dpopValidatorsMap.put(issuerConfig.getIssuerIdentifier(), dpopValidator);
                LOGGER.debug("Pre-created DpopProofValidator for issuer: %s", issuerConfig.getIssuerIdentifier());
            }
        }
        Map<String, DpopProofValidator> dpopValidators = Map.copyOf(dpopValidatorsMap);

        // Use default cache config if not provided
        if (cacheConfig == null) {
            cacheConfig = AccessTokenCacheConfig.defaultConfig();
        }

        // Construct TokenStringValidator for pre-pipeline validation
        // When JWE is configured, use the larger maxEncryptedTokenSize
        this.tokenStringValidator = new TokenStringValidator(
                parserConfig, this.securityEventCounter, jweDecryptionConfig);
        LOGGER.debug("TokenStringValidator initialized");

        // Construct RefreshTokenValidationPipeline (minimal validation, no cache, no metrics, no security events)
        // Uses jwtParser.decodeOpaqueToken() internally to avoid false-positive events for opaque tokens
        this.refreshTokenPipeline = new RefreshTokenValidationPipeline(jwtParser);
        LOGGER.debug("RefreshTokenValidationPipeline initialized");

        // Construct IdTokenValidationPipeline (full validation, no cache, no metrics)
        this.idTokenPipeline = new IdTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                signatureValidators,
                tokenBuilders,
                claimValidators,
                headerValidators,
                this.securityEventCounter);
        LOGGER.debug("IdTokenValidationPipeline initialized");

        // Compute maximum clock skew across all issuers for cache expiration tolerance.
        // The cache is shared across issuers, so we use the most lenient skew to avoid
        // evicting tokens that would still be valid for their respective issuer.
        int maxClockSkew = enabledIssuerConfigs.stream()
                .mapToInt(IssuerConfig::getClockSkewSeconds)
                .max()
                .orElse(0);

        // Construct AccessTokenValidationPipeline (full validation, with cache and metrics)
        // Pipeline creates its own AccessTokenCache from config
        this.accessTokenPipeline = new AccessTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                signatureValidators,
                tokenBuilders,
                claimValidators,
                headerValidators,
                dpopValidators,
                tokenValidationRules,
                cacheConfig,
                this.securityEventCounter,
                this.performanceMonitor,
                maxClockSkew);
        LOGGER.debug("AccessTokenValidationPipeline initialized with cache maxSize=%s, evictionInterval=%ss",
                cacheConfig.getMaxSize(), cacheConfig.getEvictionIntervalSeconds());

        LOGGER.info(JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED,
                "%s enabled issuer(s): %s".formatted(enabledIssuerConfigs.size(),
                        enabledIssuerConfigs.stream().map(IssuerConfig::getIssuerIdentifier).toList()));

        if (jweDecryptionConfig != null) {
            LOGGER.info(JWTValidationLogMessages.INFO.JWE_DECRYPTION_ENABLED, jweDecryptionConfig.getKeyCount());
        }
    }


    /**
     * Creates an access token from the given request.
     *
     * @param request the access token validation request containing the token string and HTTP headers
     * @return The parsed access token
     * @throws TokenValidationException if the token is invalid
     */
    public AccessTokenContent createAccessToken(AccessTokenRequest request) {
        LOGGER.debug("Creating access token");

        // Record complete validation time
        MetricsTicker completeTicker = MetricsTickerFactory.createStartedTicker(MeasurementType.COMPLETE_VALIDATION, performanceMonitor);
        try {
            // Pre-pipeline validation (null, blank, size)
            tokenStringValidator.validate(request.tokenString());

            // Delegate to access token pipeline (handles caching, metrics, full validation)
            AccessTokenContent result = accessTokenPipeline.validate(request);

            LOGGER.debug("Successfully created access token");
            securityEventCounter.increment(SecurityEventCounter.EventType.ACCESS_TOKEN_CREATED);

            return result;
        } finally {
            completeTicker.stopAndRecord();
        }
    }

    /**
     * Creates an ID token from the given request.
     *
     * @param request the ID token validation request containing the token string and HTTP headers
     * @return The parsed ID token
     * @throws TokenValidationException if the token is invalid
     */
    public IdTokenContent createIdToken(IdTokenRequest request) {
        LOGGER.debug("Creating ID token");

        // Pre-pipeline validation (null, blank, size)
        tokenStringValidator.validate(request.tokenString());

        // Delegate to ID token pipeline (handles full validation, no caching, no metrics)
        IdTokenContent validatedToken = idTokenPipeline.validate(request);

        LOGGER.debug("Successfully created ID-Token");
        securityEventCounter.increment(SecurityEventCounter.EventType.ID_TOKEN_CREATED);

        return validatedToken;
    }

    /**
     * Creates a refresh token from the given request.
     *
     * @param request the refresh token validation request containing the token string and HTTP headers
     * @return The parsed refresh token
     * @throws TokenValidationException if the token is invalid
     */
    public UnvalidatedRefreshToken createRefreshToken(RefreshTokenRequest request) {
        LOGGER.debug("Creating refresh token");

        // Pre-pipeline validation (null, blank, size)
        tokenStringValidator.validate(request.tokenString());

        // Delegate to refresh token pipeline (handles minimal validation, no caching, no metrics)
        UnvalidatedRefreshToken refreshToken = refreshTokenPipeline.validate(request);

        LOGGER.debug("Successfully created Refresh-Token");
        securityEventCounter.increment(SecurityEventCounter.EventType.REFRESH_TOKEN_CREATED);

        return refreshToken;
    }

    /**
     * Shuts down internal resources (cache eviction executor, DPoP replay protection).
     * This should be called when the TokenValidator is no longer needed.
     */
    @Override
    public void close() {
        accessTokenPipeline.shutdown();
        if (dpopReplayProtection != null) {
            dpopReplayProtection.close();
        }
    }
}
