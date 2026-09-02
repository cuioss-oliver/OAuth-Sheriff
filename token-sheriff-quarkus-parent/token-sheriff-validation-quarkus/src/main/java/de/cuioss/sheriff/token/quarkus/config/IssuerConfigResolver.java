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
package de.cuioss.sheriff.token.quarkus.config;

import de.cuioss.http.client.adapter.RetryConfig;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.mapper.ClaimMapperRegistry;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.tools.logging.CuiLogger;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * Resolver for creating {@link IssuerConfig} instances from Quarkus configuration properties.
 * <p>
 * This class handles the complex logic of discovering issuer configurations from properties,
 * validating mutual exclusivity constraints, and creating properly configured IssuerConfig instances.
 * It uses the template-based property key system for dynamic issuer configuration.
 * </p>
 * <p>
 * The resolver supports all JWKS source types:
 * <ul>
 *   <li>HTTP JWKS URL - Direct JWKS endpoint</li>
 *   <li>Well-known discovery - OpenID Connect discovery</li>
 *   <li>File path - Local JWKS file</li>
 *   <li>Inline content - JWKS content as string</li>
 * </ul>
 * <p>
 * Configuration validation is delegated to the underlying builders, ensuring consistency
 * with the core validation logic without duplication.
 * </p>
 *
 * @since 1.0
 */
public class IssuerConfigResolver {

    private static final CuiLogger LOGGER = new CuiLogger(IssuerConfigResolver.class);

    private final Config config;
    private final RetryConfig retryConfig;
    private final @Nullable ClaimMapperRegistry claimMapperRegistry;
    private final @Nullable ParserConfig parserConfig;

    /**
     * Creates a new IssuerConfigResolver with the specified configuration, retry config,
     * claim mapper registry, and pre-initialized parser configuration.
     *
     * @param config the configuration instance to use for property resolution
     * @param retryConfig the retry configuration to use for HTTP operations
     * @param claimMapperRegistry the registry of CDI-discovered claim mappers, may be {@code null}
     * @param parserConfig the pre-initialized parser configuration, may be {@code null}
     */
    public IssuerConfigResolver(Config config, RetryConfig retryConfig,
            @Nullable ClaimMapperRegistry claimMapperRegistry, @Nullable ParserConfig parserConfig) {
        this.config = config;
        this.retryConfig = retryConfig;
        this.claimMapperRegistry = claimMapperRegistry;
        this.parserConfig = parserConfig;
    }

    /**
     * Resolves all enabled issuer configurations from properties.
     * <p>
     * This method discovers all configured issuers by scanning properties with the
     * issuer template pattern, validates each configuration, and creates IssuerConfig
     * instances using the appropriate builders.
     * </p>
     * <p>
     * Validation is performed by the underlying builders, ensuring that configuration
     * errors are caught early with appropriate error messages.
     * </p>
     *
     * @return list of valid, enabled IssuerConfig instances
     * @throws IllegalStateException if no enabled issuers are found or configuration is invalid
     */
   
    public List<IssuerConfig> resolveIssuerConfigs() {
        LOGGER.info(INFO.RESOLVING_ISSUER_CONFIGURATIONS);

        Set<String> issuerNames = discoverIssuerNames(config);
        if (issuerNames.isEmpty()) {
            throw new IllegalStateException("No issuer configurations found in properties");
        }

        List<IssuerConfig> enabledIssuers = new ArrayList<>();
        for (String issuerName : issuerNames) {
            LOGGER.debug("Resolving issuer configuration for %s", issuerName);
            if (isIssuerEnabled(config, issuerName)) {
                IssuerConfig issuerConfig = createIssuerConfig(issuerName);
                enabledIssuers.add(issuerConfig);
                LOGGER.info(INFO.RESOLVED_ISSUER_CONFIGURATION, issuerName);
            } else {
                LOGGER.debug("Skipping disabled issuer: %s", issuerName);
            }
        }

        if (enabledIssuers.isEmpty()) {
            throw new IllegalStateException("No enabled issuer configurations found");
        }

        LOGGER.info(INFO.RESOLVED_ENABLED_ISSUER_CONFIGURATIONS, enabledIssuers.size());
        return enabledIssuers;
    }

    /**
     * Probes whether the {@code sheriff.token.issuers.*} namespace yields at least one enabled issuer.
     * <p>
     * This reads only MicroProfile {@link Config} — it builds no {@link IssuerConfig} and touches no
     * CDI bean, so callers can ask "is the extension configured at all?" without triggering the
     * fail-fast behavior of {@link #resolveIssuerConfigs()}.
     * </p>
     *
     * @param config the configuration instance to probe
     * @return {@code true} if at least one discovered issuer is enabled, {@code false} otherwise
     */
    public static boolean hasEnabledIssuers(Config config) {
        return discoverIssuerNames(config).stream()
                .anyMatch(issuerName -> isIssuerEnabled(config, issuerName));
    }

    /**
     * Discovers all configured issuer names by scanning properties.
     * <p>
     * Scans all property names for the issuer template pattern and extracts
     * the issuer names from matching properties.
     * </p>
     *
     * @param config the configuration instance to scan
     * @return set of discovered issuer names
     */
    private static Set<String> discoverIssuerNames(Config config) {
        Set<String> issuerNames = ConfigValueParser.discoverNameSegments(
                config, JwtPropertyKeys.PREFIX + ".issuers.");
        LOGGER.debug("Discovered issuer names: %s", issuerNames);
        return issuerNames;
    }

    /**
     * Checks if an issuer is enabled in the configuration.
     *
     * @param config the configuration instance to read
     * @param issuerName the issuer name
     * @return true if the issuer is enabled, false otherwise
     */
    private static boolean isIssuerEnabled(Config config, String issuerName) {
        return config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted(issuerName),
                Boolean.class
        ).orElse(false); // Default to disabled — require explicit enabled=true
    }

    /**
     * Creates an IssuerConfig for the specified issuer name.
     * <p>
     * This method builds the IssuerConfig using the builder pattern, allowing
     * the builder to perform all validation logic. Configuration errors are
     * wrapped in more descriptive exceptions for Quarkus context.
     * </p>
     *
     * @param issuerName the issuer name
     * @return configured IssuerConfig instance
     * @throws IllegalArgumentException if configuration is invalid
     */
    private IssuerConfig createIssuerConfig(String issuerName) {
        IssuerConfig.IssuerConfigBuilder builder = IssuerConfig.builder()
                .enabled(true);

        // Configure core properties
        Optional<String> resolvedIssuerIdentifier = configureIssuerIdentifier(builder, issuerName);
        configureAudience(builder, issuerName);
        configureClientId(builder, issuerName);
        configureAlgorithmPreferences(builder, issuerName);
        configureClaimSubOptional(builder, issuerName);
        configureAccessTokenAudienceOptional(builder, issuerName);
        configureExpectedTokenType(builder, issuerName);
        configureClockSkew(builder, issuerName);
        configureMaxTokenAge(builder, issuerName);
        configureDpop(builder, issuerName);

        // Configure JWKS source (mutually exclusive)
        configureJwksSource(builder, issuerName, resolvedIssuerIdentifier);

        // Configure discovered claim mappers (applied globally to all issuers)
        configureDiscoveredClaimMappers(builder);

        // Let the builder validate and create the instance
        return builder.build();
    }

    /**
     * Configures the issuer identifier from properties.
     * <p>
     * The issuer identifier is required for most JWKS sources except well-known discovery.
     * The builder will validate this requirement.
     * </p>
     */
    private Optional<String> configureIssuerIdentifier(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<String> issuerIdentifier = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(issuerName),
                String.class
        );

        if (issuerIdentifier.isPresent()) {
            builder.issuerIdentifier(issuerIdentifier.get());
            LOGGER.debug("Set issuer identifier for %s: %s", issuerName, issuerIdentifier.get());
        }
        return issuerIdentifier;
    }

    /**
     * Configures expected audience values from properties.
     */
    private void configureAudience(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<String> audienceString = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.EXPECTED_AUDIENCE.formatted(issuerName),
                String.class
        );

        if (audienceString.isPresent()) {
            List<String> audiences = ConfigValueParser.splitCsv(audienceString.get());
            audiences.forEach(builder::expectedAudience);
            LOGGER.debug("Set expected audiences for %s: %s", issuerName, audiences);
        }

        // Allow explicit opt-out of audience validation
        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(issuerName),
                Boolean.class
        ).ifPresent(builder::audienceValidationDisabled);
    }

    /**
     * Configures expected client ID values from properties.
     */
    private void configureClientId(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<String> clientIdString = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.EXPECTED_CLIENT_ID.formatted(issuerName),
                String.class
        );

        if (clientIdString.isPresent()) {
            List<String> clientIds = ConfigValueParser.splitCsv(clientIdString.get());
            clientIds.forEach(builder::expectedClientId);
            LOGGER.debug("Set expected client IDs for %s: %s", issuerName, clientIds);
        }
    }

    /**
     * Configures algorithm preferences from properties.
     */
    private void configureAlgorithmPreferences(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<String> algorithmsString = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ALGORITHM_PREFERENCES.formatted(issuerName),
                String.class
        );

        if (algorithmsString.isPresent()) {
            List<String> algorithms = ConfigValueParser.splitCsv(algorithmsString.get());

            SignatureAlgorithmPreferences preferences = new SignatureAlgorithmPreferences(algorithms);

            builder.algorithmPreferences(preferences);
            LOGGER.debug("Set algorithm preferences for %s: %s", issuerName, algorithms);
        }
    }

    /**
     * Configures claim subject optional flag from properties.
     */
    private void configureClaimSubOptional(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<Boolean> claimSubOptional = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.CLAIM_SUB_OPTIONAL.formatted(issuerName),
                Boolean.class
        );

        if (claimSubOptional.isPresent()) {
            builder.claimSubOptional(claimSubOptional.get());
            LOGGER.debug("Set claim subject optional for %s: %s", issuerName, claimSubOptional.get());
        }
    }

    /**
     * Configures access token audience optional flag from properties.
     */
    private void configureAccessTokenAudienceOptional(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<Boolean> accessTokenAudienceOptional = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ACCESS_TOKEN_AUDIENCE_OPTIONAL.formatted(issuerName),
                Boolean.class
        );

        if (accessTokenAudienceOptional.isPresent()) {
            builder.accessTokenAudienceOptional(accessTokenAudienceOptional.get());
            LOGGER.debug("Set access token audience optional for %s: %s", issuerName, accessTokenAudienceOptional.get());
        }
    }

    /**
     * Configures the expected token type from properties.
     */
    private void configureExpectedTokenType(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<String> expectedTokenType = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.EXPECTED_TOKEN_TYPE.formatted(issuerName),
                String.class
        );

        if (expectedTokenType.isPresent()) {
            builder.expectedTokenType(expectedTokenType.get());
            LOGGER.debug("Set expected token type for %s: %s", issuerName, expectedTokenType.get());
        }
    }

    /**
     * Configures clock skew tolerance from properties.
     */
    private void configureClockSkew(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<Integer> clockSkewSeconds = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.CLOCK_SKEW_SECONDS.formatted(issuerName),
                Integer.class
        );

        if (clockSkewSeconds.isPresent()) {
            builder.clockSkewSeconds(clockSkewSeconds.get());
            LOGGER.debug("Set clock skew seconds for %s: %s", issuerName, clockSkewSeconds.get());
        }
    }

    /**
     * Configures maximum token age from properties.
     */
    private void configureMaxTokenAge(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        Optional<Integer> maxTokenAgeSeconds = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.MAX_TOKEN_AGE_SECONDS.formatted(issuerName),
                Integer.class
        );

        if (maxTokenAgeSeconds.isPresent()) {
            builder.maxTokenAgeSeconds(maxTokenAgeSeconds.get());
            LOGGER.debug("Set max token age seconds for %s: %s", issuerName, maxTokenAgeSeconds.get());
        }
    }

    /**
     * Configures DPoP (Demonstrating Proof of Possession) settings per RFC 9449.
     * <p>
     * DPoP is only activated when {@code dpop.enabled=true}. If any other
     * {@code dpop.*} sub-property is configured without {@code dpop.enabled=true},
     * an {@link IllegalStateException} is thrown at startup to prevent silently
     * disabled DPoP validation.
     * </p>
     *
     * @throws IllegalStateException if a dpop sub-property is configured while DPoP is not enabled
     */
    private void configureDpop(IssuerConfig.IssuerConfigBuilder builder, String issuerName) {
        boolean dpopEnabled = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(issuerName),
                Boolean.class
        ).orElse(false);

        if (!dpopEnabled) {
            validateNoOrphanedDpopProperties(issuerName);
            return;
        }

        DpopConfig.DpopConfigBuilder dpopBuilder = DpopConfig.builder();

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.DPOP_REQUIRED.formatted(issuerName),
                Boolean.class
        ).ifPresent(dpopBuilder::required);

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.DPOP_PROOF_MAX_AGE_SECONDS.formatted(issuerName),
                Long.class
        ).ifPresent(dpopBuilder::proofMaxAgeSeconds);

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_SIZE.formatted(issuerName),
                Integer.class
        ).ifPresent(dpopBuilder::nonceCacheSize);

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_TTL_SECONDS.formatted(issuerName),
                Long.class
        ).ifPresent(dpopBuilder::nonceCacheTtlSeconds);

        var dpopConfig = dpopBuilder.build();
        builder.dpopConfig(dpopConfig);
        LOGGER.debug("Configured DPoP for %s: required=%s", issuerName,
                dpopConfig.isRequired());
    }

    /**
     * Fails fast when any {@code dpop.*} sub-property is configured while DPoP is
     * not enabled for the issuer. Without this check, such a configuration would
     * silently disable DPoP validation.
     *
     * @param issuerName the issuer name
     * @throws IllegalStateException naming the offending property when a dpop sub-property is present
     */
    private void validateNoOrphanedDpopProperties(String issuerName) {
        List<String> dpopSubProperties = List.of(
                JwtPropertyKeys.ISSUERS.DPOP_REQUIRED.formatted(issuerName),
                JwtPropertyKeys.ISSUERS.DPOP_PROOF_MAX_AGE_SECONDS.formatted(issuerName),
                JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_SIZE.formatted(issuerName),
                JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_TTL_SECONDS.formatted(issuerName));

        for (String property : dpopSubProperties) {
            if (config.getOptionalValue(property, String.class).isPresent()) {
                throw new IllegalStateException(
                        ("Property '%s' is configured but DPoP validation is not enabled for issuer '%s'. "
                                + "Set '%s' to 'true' to activate DPoP validation, or remove the dpop.* properties.")
                                .formatted(property, issuerName,
                                        JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(issuerName)));
            }
        }
    }

    /**
     * Configures the JWKS source for the issuer.
     * <p>
     * This method handles the mutually exclusive JWKS sources:
     * HTTP URL, well-known discovery, file path, and inline content.
     * The builder will validate mutual exclusivity constraints.
     * </p>
     */
    private void configureJwksSource(IssuerConfig.IssuerConfigBuilder builder, String issuerName, Optional<String> resolvedIssuerIdentifier) {
        // HTTP JWKS URL
        Optional<String> jwksUrl = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(issuerName),
                String.class
        );

        // Well-known discovery
        Optional<String> wellKnownUrl = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(issuerName),
                String.class
        );

        // File path
        Optional<String> filePath = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted(issuerName),
                String.class
        );

        // Inline content
        Optional<String> content = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.JWKS_CONTENT.formatted(issuerName),
                String.class
        );

        // Check for HTTP-based JWKS sources (mutually exclusive)
        if (jwksUrl.isPresent() || wellKnownUrl.isPresent()) {
            HttpJwksLoaderConfig httpConfig = createHttpJwksLoaderConfig(
                    issuerName,
                    jwksUrl.orElse(null),
                    wellKnownUrl.orElse(null),
                    resolvedIssuerIdentifier
            );
            builder.httpJwksLoaderConfig(httpConfig);

            if (jwksUrl.isPresent()) {
                LOGGER.debug("Configured HTTP JWKS URL for %s: %s", issuerName, jwksUrl.get());
            } else {
                LOGGER.debug("Configured well-known discovery for %s: %s", issuerName, wellKnownUrl.get());
            }

        } else if (filePath.isPresent()) {
            builder.jwksFilePath(filePath.get());
            LOGGER.debug("Configured JWKS file path for %s: %s", issuerName, filePath.get());

        } else if (content.isPresent()) {
            builder.jwksContent(content.get());
            LOGGER.debug("Configured inline JWKS content for %s", issuerName);
        }
    }

    /**
     * Creates an HttpJwksLoaderConfig for HTTP-based JWKS loading.
     * <p>
     * Uses builder defaults for optional values, letting the builder handle validation.
     * </p>
     * <p>
     * Package-private rather than private so tests can assert the transport settings on the
     * returned configuration directly: {@link IssuerConfig} keeps no accessor for the
     * {@link HttpJwksLoaderConfig} it is built from, so the settings threaded in here are not
     * observable through {@link #resolveIssuerConfigs()}.
     * </p>
     */
    HttpJwksLoaderConfig createHttpJwksLoaderConfig(String issuerName, @Nullable String jwksUrl,
            @Nullable String wellKnownUrl, Optional<String> resolvedIssuerIdentifier) {
        HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder builder = HttpJwksLoaderConfig.builder();

        // Use the already-resolved issuer identifier (required for HTTP JWKS configuration)
        builder.issuerIdentifier(resolvedIssuerIdentifier.orElseThrow(() -> new IllegalStateException(
                "Issuer '%s' requires explicit 'issuer-identifier' when using HTTP JWKS or well-known discovery. Configure '%s' in application properties."
                        .formatted(issuerName, JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(issuerName)))));

        // Configure URLs - let the builder handle mutual exclusivity validation
        if (jwksUrl != null) {
            builder.jwksUrl(jwksUrl);
        }
        if (wellKnownUrl != null) {
            builder.wellKnownUrl(wellKnownUrl);
        }

        // Secure-by-default transport opt-ins (default false when unset).
        // The builder threads both flags into the internal WellKnownConfig (discovery fetch)
        // AND the JWKS HttpHandler / EgressPolicy (advertised jwks_uri), so a single opt-in
        // covers both the well-known discovery fetch and the JWKS URI.
        boolean allowInsecureHttp = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ALLOW_INSECURE_HTTP.formatted(issuerName),
                Boolean.class
        ).orElse(false);
        if (allowInsecureHttp) {
            builder.allowInsecureHttp(true);
            LOGGER.debug("Enabled cleartext HTTP for %s (allow-insecure-http=true)", issuerName);
        }

        // Inverted polarity relative to the opt-ins above: hostname verification is ON by default,
        // so this is an opt-OUT. Only an explicit "false" touches the builder — leaving it untouched
        // on the default path keeps the upstream HttpJwksLoaderConfigBuilder default authoritative.
        boolean verifyHostname = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.VERIFY_HOSTNAME.formatted(issuerName),
                Boolean.class
        ).orElse(true);
        if (!verifyHostname) {
            builder.verifyHostname(false);
            LOGGER.debug("Disabled TLS hostname verification for %s (verify-hostname=false)", issuerName);
        }

        boolean allowLoopbackEgress = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ALLOW_LOOPBACK_EGRESS.formatted(issuerName),
                Boolean.class
        ).orElse(false);
        if (allowLoopbackEgress) {
            builder.allowLoopbackEgress(true);
            LOGGER.debug("Enabled loopback egress for %s (allow-loopback-egress=true)", issuerName);
        }

        // Explicit egress host allow-list — needed to reach Docker-internal service names
        // (site-local bridge addresses) that allow-loopback-egress does NOT cover.
        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.ALLOWED_EGRESS_HOSTS.formatted(issuerName),
                String.class
        ).ifPresent(hostsCsv -> {
            List<String> hosts = ConfigValueParser.splitCsv(hostsCsv);
            hosts.forEach(builder::allowedEgressHost);
            if (!hosts.isEmpty()) {
                LOGGER.debug("Allow-listed egress hosts for %s: %s", issuerName, hosts);
            }
        });

        // Configure HTTP timeouts (use builder defaults if not specified)
        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted(issuerName),
                Integer.class
        ).ifPresent(builder::refreshIntervalSeconds);

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.CONNECT_TIMEOUT_SECONDS.formatted(issuerName),
                Integer.class
        ).ifPresent(builder::connectTimeoutSeconds);

        config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.READ_TIMEOUT_SECONDS.formatted(issuerName),
                Integer.class
        ).ifPresent(builder::readTimeoutSeconds);

        // Configure key rotation grace period (Issue #110)
        Optional<Integer> gracePeriodSeconds = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.KEY_ROTATION_GRACE_PERIOD_SECONDS.formatted(issuerName),
                Integer.class
        );
        if (gracePeriodSeconds.isPresent()) {
            builder.keyRotationGracePeriod(Duration.ofSeconds(gracePeriodSeconds.get()));
            LOGGER.debug("Set key rotation grace period for %s: %s seconds", issuerName, gracePeriodSeconds.get());
        }

        Optional<Integer> maxRetiredSets = config.getOptionalValue(
                JwtPropertyKeys.ISSUERS.MAX_RETIRED_KEY_SETS.formatted(issuerName),
                Integer.class
        );
        if (maxRetiredSets.isPresent()) {
            builder.maxRetiredKeySets(maxRetiredSets.get());
            LOGGER.debug("Set max retired key sets for %s: %s", issuerName, maxRetiredSets.get());
        }

        // Set the retry configuration
        builder.retryConfig(retryConfig);

        // Forward pre-initialized ParserConfig if available
        if (parserConfig != null) {
            builder.parserConfig(parserConfig);
        }

        // Let the builder validate and create the instance
        return builder.build();
    }

    /**
     * Configures discovered claim mappers from the registry.
     * <p>
     * Adds all enabled CDI-discovered claim mappers to the issuer configuration.
     * These mappers are applied globally to all configured issuers.
     * </p>
     */
    private void configureDiscoveredClaimMappers(IssuerConfig.IssuerConfigBuilder builder) {
        if (claimMapperRegistry == null) {
            return;
        }
        for (String claimName : claimMapperRegistry.getRegisteredClaimNames()) {
            claimMapperRegistry.getMapper(claimName).ifPresent(mapper -> {
                builder.claimMapper(claimName, mapper);
                LOGGER.debug("Added discovered claim mapper for claim: %s", claimName);
            });
        }
    }
}
