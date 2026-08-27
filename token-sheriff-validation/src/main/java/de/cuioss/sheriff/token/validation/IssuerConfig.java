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
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.commons.transport.LoadingStatusProvider;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.jwks.JwksLoaderFactory;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.jspecify.annotations.Nullable;

import java.util.*;

/**
 * Configuration class for issuer settings.
 * It aggregates all information needed to validate a JWT token.
 * <p>
 * This class contains the issuer URL, expected audience, expected client ID,
 * configuration for JwksLoader and {@link SignatureAlgorithmPreferences}.
 * </p>
 * <p>
 * The JwksLoader is initialized through {@link IssuerConfigCache}, which calls
 * {@link JwksLoader#initJWKSLoader(SecurityEventCounter)} asynchronously.
 * The loaded keys can be accessed through the {@link #jwksLoader} field.
 * </p>
 * <p>
 * This class is immutable after construction and thread-safe once the JwksLoader is initialized.
 * </p>
 * <p>
 * Usage example:
 * <pre>
 * // Create an issuer configuration with HTTP-based JWKS loading (well-known discovery)
 * IssuerConfig issuerConfig = IssuerConfig.builder()
 *     .issuerIdentifier("https://example.com")
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(HttpJwksLoaderConfig.builder()
 *         .wellKnownUrl("https://example.com/.well-known/openid-configuration")
 *         .refreshIntervalSeconds(60)
 *         .build())
 *     .build(); // Validation happens automatically during build()
 *
 * // Initialize the security event counter -> This is usually done by TokenValidator
 * issuerConfig.initJWKSLoader(new SecurityEventCounter());
 *
 * String issuer = issuerConfig.getIssuerIdentifier();
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-3">VALIDATION-3: Multi-Issuer Support</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4">VALIDATION-4: Key Management</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.4">VALIDATION-8.4: Claims Validation</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#_issuerconfig_and_multi_issuer_support">Technical Components Specification - IssuerConfig and Multi-Issuer Support</a>
 *
 * @since 1.0
 */
// doNotUseGetters: getIssuerIdentifier() intentionally throws for disabled configs,
// which must remain safe to log/compare (e.g. ISSUER_CONFIG_SKIPPED)
@EqualsAndHashCode(doNotUseGetters = true)
@ToString(doNotUseGetters = true)
public class IssuerConfig implements LoadingStatusProvider {

    private static final CuiLogger LOGGER = new CuiLogger(IssuerConfig.class);

    /**
     * Default clock skew tolerance in seconds.
     *
     * @see #clockSkewSeconds
     */
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

    /**
     * Whether this issuer configuration is enabled.
     * <p>
     * When set to {@code false}, this issuer configuration will be ignored during
     * token validation and will not attempt to use the underlying {@link JwksLoader}.
     * This allows for easy enabling/disabling of specific issuers without removing
     * their configuration.
     * <p>
     * Default value is {@code true}.
     */
    @Getter
    private final boolean enabled;

    /**
     * The issuer identifier for token validation.
     * <p>
     * This field is required for all enabled issuer configurations, regardless of the
     * JWKS loading variant. For well-known discovery, the discovered issuer is compared
     * against this value and a mismatch is logged as a security event, but this configured
     * value is always authoritative.
     * </p>
     * <p>
     * This identifier must match the "iss" claim in validated tokens.
     * </p>
     */
    @Nullable
    private final String issuerIdentifier;

    /**
     * Set of expected audience values.
     * These values are matched against the "aud" claim in the token.
     * If the token's audience claim matches any of these values, it is considered valid.
     * <p>
     * Either this must be non-empty or {@link #audienceValidationDisabled} must be set to
     * {@code true}. An empty audience set with validation enabled will fail at build time.
     */
    @Getter
    private final Set<String> expectedAudience;

    /**
     * Whether audience validation is explicitly disabled for this issuer.
     * <p>
     * When {@code true}, audience validation is skipped regardless of {@link #expectedAudience}.
     * When {@code false} (default), {@link #expectedAudience} must be non-empty.
     * <p>
     * Default value is {@code false} (audience validation is required).
     */
    @Getter
    private final boolean audienceValidationDisabled;

    /**
     * Set of expected client ID values.
     * These values are matched against the "azp" or "client_id" claim in the token.
     * If the token's client ID claim matches any of these values, it is considered valid.
     */
    @Getter
    private final Set<String> expectedClientId;

    /**
     * Whether the "sub" (subject) claim is optional for this issuer.
     * <p>
     * Design Decision: pragmatic accommodation for identity providers (e.g., Keycloak) that omit
     * the subject claim in access tokens. Default is secure ({@code false}). This is intentional
     * and not a compatibility workaround.
     * <p>
     * When set to {@code true}, the mandatory claims validator will not require the "sub" claim
     * to be present in tokens from this issuer.
     * </p>
     * <p>
     * <strong>Warning:</strong> Setting this to {@code true} relaxes RFC 7519 compliance.
     * According to RFC 7519 Section 4.1.2, the "sub" claim is required for ACCESS_TOKEN and ID_TOKEN types.
     * Use this option only when necessary and ensure appropriate alternative validation mechanisms.
     * </p>
     * <p>
     * Default value is {@code false} (subject claim is mandatory, RFC compliant).
     * </p>
     *
     * @see de.cuioss.sheriff.token.validation.domain.claim.ClaimName#SUBJECT
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
     */
    @Getter
    private final boolean claimSubOptional;

    /**
     * Whether the audience ("aud") claim is optional for access tokens from this issuer.
     * <p>
     * Design Decision: pragmatic accommodation for identity providers that omit
     * the audience claim in access tokens. Default is secure ({@code false}).
     * </p>
     * <p>
     * When set to {@code true}, access tokens without an "aud" claim will pass audience
     * validation even when {@link #expectedAudience} is configured. ID tokens always
     * require the "aud" claim regardless of this setting.
     * </p>
     * <p>
     * <strong>Warning:</strong> Setting this to {@code true} means that when
     * {@code expectedAudience} is configured, an access token that simply omits the
     * "aud" claim will bypass audience validation entirely — a confused deputy risk.
     * RFC 9068 Section 4 requires "aud" for JWT access tokens. Use this option only
     * when your IdP is known to omit the "aud" claim in access tokens and you cannot
     * configure it to include it.
     * </p>
     * <p>
     * Default value is {@code false} (audience claim is required for access tokens
     * when {@code expectedAudience} is configured).
     * </p>
     *
     * @see de.cuioss.sheriff.token.validation.domain.claim.ClaimName#AUDIENCE
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068#section-4">RFC 9068 - 4. JWT Access Token Claims</a>
     */
    @Getter
    private final boolean accessTokenAudienceOptional;

    /**
     * Whether the azp→audience fallback is enabled for this issuer.
     * <p>
     * The fallback accepts a token that omits the audience ("aud") claim when its authorized-party
     * ("azp") claim matches an expected audience — conflating client identity (azp) with intended
     * recipient (aud). Default is {@code false} (fallback disabled): a genuine audience claim is
     * required and an azp match is never accepted as a substitute. Set to {@code true} only if an
     * issuer is known to omit {@code aud} and cannot be reconfigured.
     * </p>
     */
    @Getter
    private final boolean azpAudienceFallbackEnabled;

    /**
     * Whether the RFC 9068 {@code client_id}→{@code azp} fallback is enabled for this issuer.
     * <p>
     * The fallback accepts a token that omits the {@code azp} claim when its {@code client_id} claim
     * matches an expected client ID. Default is {@code false} (fallback disabled): a genuine
     * {@code azp} claim is required and a {@code client_id} match is never accepted as a substitute.
     * Set to {@code true} only if an issuer is known to omit {@code azp} and cannot be reconfigured.
     * </p>
     */
    @Getter
    private final boolean clientIdFallbackEnabled;

    // Design Decision: expectedTokenType defaults to null (no token type validation).
    //
    // RFC 9068 Section 2.1 requires typ: at+jwt for JWT access tokens, and validating this
    // would prevent token type confusion attacks (e.g., substituting an ID token for an
    // access token). However, most major IdPs do NOT set typ: at+jwt:
    //   - Keycloak sets typ: JWT
    //   - Zitadel sets typ: JWT or omits it
    //   - Dex omits the typ header entirely
    //   - Azure AD B2C uses proprietary typ values
    //
    // Defaulting to "at+jwt" would break nearly every real-world deployment. Defaulting to
    // "JWT" would accept everything and provide no security value (any JWT type passes).
    // Therefore: opt-in via expected-token-type=at+jwt for IdPs that support RFC 9068.

    /**
     * The expected value for the JWT "typ" header parameter.
     * <p>
     * When configured (e.g., {@code "at+jwt"}), the
     * {@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator}
     * will validate that the token's "typ" header matches this value.
     * The comparison is case-insensitive per RFC convention.
     * </p>
     * <p>
     * When {@code null} (default), no token type validation is performed.
     * </p>
     * <p>
     * <strong>Security recommendation:</strong> Set this to {@code "at+jwt"} if your identity
     * provider issues RFC 9068-compliant tokens. This prevents token type confusion attacks
     * (e.g., using an ID token as an access token). Most IdPs (Keycloak, Zitadel, Dex,
     * Azure AD B2C) do not set {@code typ: at+jwt} by default — verify your IdP's behavior
     * before enabling.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068#section-2.1">RFC 9068 - 2.1. Header</a>
     */
    @Getter
    @Nullable
    private final String expectedTokenType;

    /**
     * Optional DPoP (Demonstrating Proof of Possession) configuration per RFC 9449.
     * <p>
     * When non-null, DPoP validation is enabled for this issuer. Tokens containing
     * a {@code cnf.jkt} claim will be validated against a DPoP proof JWT from
     * the {@code DPoP} HTTP header.
     * </p>
     * <p>
     * When {@code null} (default), DPoP validation is disabled and tokens are
     * treated as bearer tokens.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449</a>
     */
    @Getter
    @Nullable
    private final DpopConfig dpopConfig;

    /**
     * Clock skew tolerance in seconds for time-based claim validation (exp, nbf).
     * <p>
     * Accommodates clock drift between the token issuer and the validator in distributed systems.
     * A token is considered expired only when {@code exp + clockSkewSeconds < now}.
     * </p>
     * <p>
     * Default value is {@code 60} seconds.
     * </p>
     *
     * @see de.cuioss.sheriff.token.validation.domain.context.ValidationContext
     * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.clock.skew</a>
     */
    @Getter
    private final int clockSkewSeconds;

    /**
     * Maximum token age in seconds based on the {@code iat} claim, or {@code null} if disabled.
     * <p>
     * When set, tokens where {@code now - iat > maxTokenAgeSeconds + clockSkewSeconds}
     * are rejected, even if not yet expired. This provides an additional security control
     * beyond standard expiration checking.
     * </p>
     * <p>
     * Default value is {@code null} (disabled).
     * </p>
     *
     * @see de.cuioss.sheriff.token.validation.domain.context.ValidationContext
     * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.token.age</a>
     */
    @Getter
    @Nullable
    private final Integer maxTokenAgeSeconds;

    @Getter
    private final SignatureAlgorithmPreferences algorithmPreferences;

    /**
     * Custom claim mappers that take precedence over the default ones.
     * The key is the claim name, and the value is the mapper to use for that claim.
     */
    @Getter
    private final Map<String, ClaimMapper> claimMappers;

    /**
     * The JwksLoader instance used for loading JWKS keys.
     * This can be null initially and will be initialized
     * with the SecurityEventCounter by the TokenValidator.
     */
    @Getter
    @Nullable
    private final JwksLoader jwksLoader;


    /**
     * Gets the issuer identifier for token validation.
     * <p>
     * Returns the configured issuer identifier, which is required for all enabled
     * configurations and validated during {@link IssuerConfigBuilder#build()}.
     * For well-known discovery, the discovered issuer never overrides this value;
     * a mismatch is surfaced as a {@code ISSUER_MISMATCH} security event by the loader.
     *
     * @return the issuer identifier, never null
     * @throws IllegalStateException if called on a disabled configuration that was
     *         built without an issuer identifier
     */
    public String getIssuerIdentifier() {
        Preconditions.checkState(issuerIdentifier != null,
                "issuerIdentifier is null - it is only optional for disabled issuer configurations, which must not be used for validation");
        return issuerIdentifier;
    }

    /**
     * Checks the health status of this issuer configuration.
     * <p>
     * This method provides a unified view of both configuration state (enabled) and runtime state (healthy).
     * The health check process:
     * <ol>
     *   <li>Returns {@link LoaderStatus#UNDEFINED} immediately if the issuer is disabled</li>
     *   <li>Returns {@link LoaderStatus#UNDEFINED} if the JwksLoader is not initialized</li>
     *   <li>Delegates to the underlying {@link JwksLoader#getLoaderStatus()} method</li>
     * </ol>
     * <p>
     * This is a non-blocking status read: it never triggers loading of JWKS content itself,
     * it only reports the loader's current state. The method is designed to be fail-fast
     * and thread-safe.
     * <p>
     * The status reflects the combined state of configuration and runtime health:
     * <ul>
     *   <li>{@link LoaderStatus#UNDEFINED} - Issuer is disabled or JwksLoader not initialized</li>
     *   <li>{@link LoaderStatus#OK} - Issuer is enabled and JwksLoader is healthy</li>
     *   <li>{@link LoaderStatus#ERROR} - Issuer is enabled but JwksLoader has errors</li>
     * </ul>
     *
     * @return the current health status of this issuer configuration
     */
    @Override
    public LoaderStatus getLoaderStatus() {
        // Return UNDEFINED if the issuer is disabled or jwksLoader is not configured
        if (!enabled || jwksLoader == null) {
            return LoaderStatus.UNDEFINED;
        }
        // Delegate to the underlying JwksLoader
        return jwksLoader.getLoaderStatus();
    }

    /**
     * Creates a new builder for IssuerConfig.
     *
     * @return a new IssuerConfigBuilder instance
     */
    public static IssuerConfigBuilder builder() {
        return new IssuerConfigBuilder();
    }

    /**
     * Custom builder class that includes validation in the build() method.
     * <p>
     * This builder provides a fluent API for constructing {@link IssuerConfig} instances with proper validation.
     * It supports various JWKS loading methods including HTTP-based discovery, file-based loading, and in-memory content.
     * </p>
     * <p>
     * The builder validates configuration consistency during the {@link #build()} method call, ensuring that:
     * <ul>
     *   <li>At least one JWKS loading method is configured for enabled issuers</li>
     *   <li>Issuer identifier is provided for enabled issuers</li>
     *   <li>Algorithm preferences and claim mappers are properly initialized</li>
     * </ul>
     */
    @SuppressWarnings("JavadocLinkAsPlainText")
    public static class IssuerConfigBuilder {
        private boolean enabled = true;
        private @Nullable String issuerIdentifier;
        private @Nullable Set<String> expectedAudience;
        private boolean audienceValidationDisabled = false;
        private @Nullable Set<String> expectedClientId;
        private boolean claimSubOptional = false;
        private boolean accessTokenAudienceOptional = false;
        private boolean azpAudienceFallbackEnabled = false;
        private boolean clientIdFallbackEnabled = false;
        private @Nullable String expectedTokenType;
        private @Nullable DpopConfig dpopConfig;
        private int clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        private @Nullable Integer maxTokenAgeSeconds;
        private SignatureAlgorithmPreferences algorithmPreferences = new SignatureAlgorithmPreferences();
        private @Nullable Map<String, ClaimMapper> claimMappers;
        private @Nullable JwksLoader jwksLoader;

        private @Nullable HttpJwksLoaderConfig httpJwksLoaderConfig;
        private @Nullable String jwksFilePath;
        private @Nullable String jwksContent;

        /**
         * Sets whether this issuer configuration is enabled.
         * <p>
         * When set to {@code false}, this issuer configuration will be ignored during token validation
         * and will not attempt to use the underlying {@link JwksLoader}. This allows for easy
         * enabling/disabling of specific issuers without removing their configuration.
         * </p>
         * <p>
         * Default value is {@code true}.
         * </p>
         *
         * @param enabled {@code true} to enable this issuer configuration, {@code false} to disable it
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        /**
         * Sets the issuer identifier for token validation.
         * <p>
         * This identifier must match the "iss" claim in validated tokens. It is required for
         * all enabled issuer configurations, regardless of the JWKS loading variant. For
         * well-known discovery, set it to the issuer URL of the discovery document; a mismatch
         * with the discovered issuer is reported as a security event.
         * </p>
         * <p>
         * Examples:
         * <ul>
         *   <li>{@code "https://auth.example.com"} - Standard OIDC issuer URL</li>
         *   <li>{@code "https://accounts.google.com"} - Google OAuth2 issuer</li>
         *   <li>{@code "internal-service"} - Internal service identifier</li>
         * </ul>
         *
         * @param issuerIdentifier the issuer identifier that must match the "iss" claim in tokens
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 - "iss" (Issuer) Claim</a>
         */
        public IssuerConfigBuilder issuerIdentifier(String issuerIdentifier) {
            this.issuerIdentifier = issuerIdentifier;
            return this;
        }

        /**
         * Adds a single expected audience value for token validation.
         * <p>
         * This value will be matched against the "aud" claim in tokens. If the token's audience
         * claim matches any of the configured expected audiences, it is considered valid.
         * Multiple audience values can be added by calling this method multiple times.
         * </p>
         * <p>
         * Examples:
         * <ul>
         *   <li>{@code "my-client-app"} - Client application identifier</li>
         *   <li>{@code "https://api.example.com"} - API endpoint URL</li>
         *   <li>{@code "urn:my-service"} - URN-based service identifier</li>
         * </ul>
         *
         * @param expectedAudience the audience value that tokens must match
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 - "aud" (Audience) Claim</a>
         */
        public IssuerConfigBuilder expectedAudience(String expectedAudience) {
            if (this.expectedAudience == null) {
                this.expectedAudience = new LinkedHashSet<>();
            }
            this.expectedAudience.add(expectedAudience);
            return this;
        }

        /**
         * Sets the complete set of expected audience values for token validation.
         * <p>
         * This replaces any previously configured audience values. The token's "aud" claim
         * must match at least one of these values for the token to be considered valid.
         * </p>
         *
         * @param expectedAudience the set of audience values that tokens must match
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 - "aud" (Audience) Claim</a>
         */
        public IssuerConfigBuilder expectedAudience(Set<String> expectedAudience) {
            this.expectedAudience = expectedAudience;
            return this;
        }

        /**
         * Explicitly disables audience validation for this issuer.
         * <p>
         * When set to {@code true}, no audience validation is performed regardless of
         * {@link #expectedAudience}. Use this only when the issuer does not include the
         * "aud" claim in tokens and audience validation is not required.
         *
         * @param audienceValidationDisabled {@code true} to disable audience validation
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder audienceValidationDisabled(boolean audienceValidationDisabled) {
            this.audienceValidationDisabled = audienceValidationDisabled;
            return this;
        }

        /**
         * Adds a single expected client ID value for token validation.
         * <p>
         * This value will be matched against the "azp" (authorized party) or "client_id" claims in tokens.
         * If the token's client ID claim matches any of the configured expected client IDs,
         * it is considered valid. Multiple client ID values can be added by calling this method multiple times.
         * </p>
         * <p>
         * Examples:
         * <ul>
         *   <li>{@code "web-app-client"} - Web application client identifier</li>
         *   <li>{@code "mobile-app-android"} - Mobile application client identifier</li>
         *   <li>{@code "service-to-service"} - Service-to-service client identifier</li>
         * </ul>
         *
         * @param expectedClientId the client ID value that tokens must match
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 - Registered Claim Names</a>
         * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core - ID Token</a>
         */
        public IssuerConfigBuilder expectedClientId(String expectedClientId) {
            if (this.expectedClientId == null) {
                this.expectedClientId = new LinkedHashSet<>();
            }
            this.expectedClientId.add(expectedClientId);
            return this;
        }

        /**
         * Sets the complete set of expected client ID values for token validation.
         * <p>
         * This replaces any previously configured client ID values. The token's "azp" or "client_id"
         * claim must match at least one of these values for the token to be considered valid.
         * </p>
         *
         * @param expectedClientId the set of client ID values that tokens must match
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 - Registered Claim Names</a>
         * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core - ID Token</a>
         */
        public IssuerConfigBuilder expectedClientId(Set<String> expectedClientId) {
            this.expectedClientId = expectedClientId;
            return this;
        }

        /**
         * Sets whether the "sub" (subject) claim is optional for this issuer.
         * <p>
         * When set to {@code true}, the mandatory claims validator will not require the "sub" claim
         * to be present in tokens from this issuer. This provides a workaround for identity providers
         * that don't include the subject claim in access tokens by default.
         * </p>
         * <p>
         * <strong>Warning:</strong> Setting this to {@code true} relaxes RFC 7519 compliance.
         * According to RFC 7519 Section 4.1.2, the "sub" claim is required for ACCESS_TOKEN and ID_TOKEN types.
         * Use this option only when necessary and ensure appropriate alternative validation mechanisms.
         * </p>
         * <p>
         * Default value is {@code false} (subject claim is mandatory, RFC compliant).
         * </p>
         *
         * @param claimSubOptional {@code true} to make the subject claim optional, {@code false} to require it (RFC compliant)
         * @return this builder instance for method chaining
         * @see de.cuioss.sheriff.token.validation.domain.claim.ClaimName#SUBJECT
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
         */
        public IssuerConfigBuilder claimSubOptional(boolean claimSubOptional) {
            this.claimSubOptional = claimSubOptional;
            return this;
        }

        /**
         * Sets whether the audience claim is optional for access tokens from this issuer.
         *
         * @param accessTokenAudienceOptional {@code true} to allow access tokens without audience claim,
         *                                     {@code false} to require it when expectedAudience is configured
         * @return this builder instance for method chaining
         * @see de.cuioss.sheriff.token.validation.domain.claim.ClaimName#AUDIENCE
         */
        public IssuerConfigBuilder accessTokenAudienceOptional(boolean accessTokenAudienceOptional) {
            this.accessTokenAudienceOptional = accessTokenAudienceOptional;
            return this;
        }

        /**
         * Sets whether the azp→audience fallback is enabled for this issuer.
         * <p>
         * When {@code false} (the default), a token that omits the audience ("aud") claim is never
         * accepted on the strength of a matching authorized-party ("azp") claim. Set to {@code true}
         * only if an issuer is known to omit {@code aud} and cannot be reconfigured.
         * </p>
         *
         * @param azpAudienceFallbackEnabled {@code true} to allow azp to substitute for a missing audience,
         *                                   {@code false} to require a genuine audience claim
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder azpAudienceFallbackEnabled(boolean azpAudienceFallbackEnabled) {
            this.azpAudienceFallbackEnabled = azpAudienceFallbackEnabled;
            return this;
        }

        /**
         * Sets whether the RFC 9068 {@code client_id}→{@code azp} fallback is enabled for this issuer.
         * <p>
         * When {@code false} (the default), a token that omits the {@code azp} claim is never accepted
         * on the strength of a matching {@code client_id} claim. Set to {@code true} only if an issuer
         * is known to omit {@code azp} and cannot be reconfigured.
         * </p>
         *
         * @param clientIdFallbackEnabled {@code true} to allow client_id to substitute for a missing azp,
         *                                {@code false} to require a genuine azp claim
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder clientIdFallbackEnabled(boolean clientIdFallbackEnabled) {
            this.clientIdFallbackEnabled = clientIdFallbackEnabled;
            return this;
        }

        /**
         * Sets the expected JWT "typ" header parameter value for this issuer.
         * <p>
         * When configured, the {@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator}
         * will validate that the token's "typ" header matches this value (e.g., "at+jwt" per RFC 9068).
         * The comparison is case-insensitive per RFC convention.
         * </p>
         * <p>
         * When not set (default), no token type validation is performed.
         * </p>
         *
         * @param expectedTokenType the expected token type value (e.g., "at+jwt")
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068</a>
         */
        public IssuerConfigBuilder expectedTokenType(String expectedTokenType) {
            this.expectedTokenType = expectedTokenType;
            return this;
        }

        /**
         * Sets the DPoP (Demonstrating Proof of Possession) configuration for this issuer.
         * <p>
         * When set, DPoP validation per RFC 9449 is enabled. Tokens with a {@code cnf.jkt}
         * claim will require a valid DPoP proof JWT in the {@code DPoP} HTTP header.
         * </p>
         *
         * @param dpopConfig the DPoP configuration, or {@code null} to disable
         * @return this builder instance for method chaining
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449</a>
         */
        public IssuerConfigBuilder dpopConfig(DpopConfig dpopConfig) {
            this.dpopConfig = dpopConfig;
            return this;
        }

        /**
         * Sets the clock skew tolerance in seconds for time-based claim validation.
         * <p>
         * Accommodates clock drift between the token issuer and the validator in distributed systems.
         * A token is considered expired only when {@code exp + clockSkewSeconds < now}.
         * </p>
         * <p>
         * Default value is {@code 60} seconds.
         * </p>
         *
         * @param clockSkewSeconds the clock skew tolerance in seconds (must be non-negative)
         * @return this builder instance for method chaining
         * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.clock.skew</a>
         */
        public IssuerConfigBuilder clockSkewSeconds(int clockSkewSeconds) {
            Preconditions.checkArgument(clockSkewSeconds >= 0, "clockSkewSeconds must not be negative, but was %s", clockSkewSeconds);
            this.clockSkewSeconds = clockSkewSeconds;
            return this;
        }

        /**
         * Sets the maximum token age in seconds based on the {@code iat} claim.
         * <p>
         * When set, tokens where {@code now - iat > maxTokenAgeSeconds + clockSkewSeconds}
         * are rejected, even if not yet expired.
         * </p>
         * <p>
         * Default value is {@code null} (disabled).
         * </p>
         *
         * @param maxTokenAgeSeconds the maximum token age in seconds, or {@code null} to disable
         * @return this builder instance for method chaining
         * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.token.age</a>
         */
        @SuppressWarnings("java:S2589") // Null check is intentional — parameter is @Nullable
        public IssuerConfigBuilder maxTokenAgeSeconds(@Nullable Integer maxTokenAgeSeconds) {
            if (null != maxTokenAgeSeconds) {
                Preconditions.checkArgument(maxTokenAgeSeconds >= 0, "maxTokenAgeSeconds must not be negative, but was %s", maxTokenAgeSeconds);
            }
            this.maxTokenAgeSeconds = maxTokenAgeSeconds;
            return this;
        }

        /**
         * Sets the signature algorithm preferences for token validation.
         * <p>
         * This configuration controls which signature algorithms are preferred and allowed
         * during token validation. It can be used to enforce security policies, such as
         * requiring stronger algorithms or blacklisting weak ones.
         * </p>
         * <p>
         * If not explicitly set, default algorithm preferences will be used that include
         * commonly used secure algorithms like RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, and PS512.
         * </p>
         * <p>
         * Example usage:
         * <pre>
         * SignatureAlgorithmPreferences preferences = SignatureAlgorithmPreferences.builder()
         *     .preferredAlgorithms(List.of("RS256", "ES256"))
         *     .allowedAlgorithms(List.of("RS256", "RS384", "ES256", "ES384"))
         *     .build();
         * builder.algorithmPreferences(preferences);
         * </pre>
         *
         * @param algorithmPreferences the signature algorithm preferences to use
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder algorithmPreferences(SignatureAlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        /**
         * Adds a custom claim mapper for a specific claim name.
         * <p>
         * Claim mappers allow custom processing of JWT claims during token validation.
         * They can be used to transform claim values, validate custom claim formats,
         * or extract nested information from complex claim structures.
         * </p>
         * <p>
         * Custom claim mappers take precedence over the default claim processing logic.
         * Multiple mappers can be added by calling this method multiple times with different claim names.
         * </p>
         * <p>
         * Example usage:
         * <pre>
         * ClaimMapper customScopeMapper = new CustomScopeMapper();
         * builder.claimMapper("scope", customScopeMapper);
         *
         * ClaimMapper rolesMapper = new RolesMapper();
         * builder.claimMapper("roles", rolesMapper);
         * </pre>
         *
         * @param key the name of the claim to apply the custom mapper to
         * @param claimMapper the custom mapper implementation for processing the claim
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder claimMapper(String key, ClaimMapper claimMapper) {
            if (this.claimMappers == null) {
                this.claimMappers = new LinkedHashMap<>();
            }
            this.claimMappers.put(key, claimMapper);
            return this;
        }

        /**
         * Sets a custom JwksLoader implementation.
         * <p>
         * This method allows providing a pre-configured custom {@link JwksLoader} instead of
         * using one of the built-in factory methods. This is useful for advanced use cases
         * where custom JWKS loading logic is required.
         * </p>
         * <p>
         * When using a custom JwksLoader, ensure that:
         * <ul>
         *   <li>The loader implements proper error handling and retry logic</li>
         *   <li>The loader's {@link JwksLoader#getJwksType()} method returns an appropriate type</li>
         *   <li>{@link #issuerIdentifier(String)} is set — it is required for all enabled configurations</li>
         * </ul>
         * <p>
         * Note: If a custom JwksLoader is provided, the other JWKS configuration methods
         * ({@link #httpJwksLoaderConfig}, {@link #jwksFilePath}, {@link #jwksContent}) will be ignored.
         * </p>
         *
         * @param jwksLoader the custom JwksLoader implementation to use
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder jwksLoader(JwksLoader jwksLoader) {
            this.jwksLoader = jwksLoader;
            return this;
        }

        // Configuration methods for different JWKS types
        /**
         * Sets the HTTP JWKS loader configuration for remote JWKS loading.
         * <p>
         * This method configures the issuer to load JWKS (JSON Web Key Set) from a remote HTTP endpoint.
         * This is the most common configuration for production environments where JWKS are served
         * by an identity provider or authorization server.
         * </p>
         * <p>
         * The HTTP loader supports several loading methods:
         * <ul>
         *   <li><strong>Direct JWKS URL:</strong> Load directly from a JWKS endpoint</li>
         *   <li><strong>Well-Known Discovery:</strong> Use OpenID Connect discovery to find the JWKS endpoint</li>
         *   <li><strong>Background Refresh:</strong> Automatically refresh JWKS in the background</li>
         *   <li><strong>Caching and ETags:</strong> Efficient caching with HTTP ETags support</li>
         * </ul>
         * <p>
         * Example configurations:
         * <pre>
         * // Direct JWKS URL
         * HttpJwksLoaderConfig directConfig = HttpJwksLoaderConfig.builder()
         *     .jwksUrl("https://auth.example.com/.well-known/jwks.json")
         *     .refreshIntervalSeconds(300) // 5 minutes
         *     .build();
         *
         * // Well-Known Discovery
         * HttpJwksLoaderConfig discoveryConfig = HttpJwksLoaderConfig.builder()
         *     .wellKnownUrl("https://auth.example.com/.well-known/openid-configuration")
         *     .refreshIntervalSeconds(600) // 10 minutes
         *     .build();
         *
         * builder.httpJwksLoaderConfig(directConfig);
         * </pre>
         * <p>
         * <strong>Important:</strong> The {@link #issuerIdentifier(String)} is required for
         * well-known discovery as well: set it to the issuer URL of the discovery document.
         * The discovered issuer is compared against it and a mismatch is reported as a
         * security event, but the configured value is authoritative.
         * </p>
         *
         * @param httpJwksLoaderConfig the HTTP JWKS loader configuration
         * @return this builder instance for method chaining
         * @see HttpJwksLoaderConfig
         * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery</a>
         */
        public IssuerConfigBuilder httpJwksLoaderConfig(HttpJwksLoaderConfig httpJwksLoaderConfig) {
            this.httpJwksLoaderConfig = httpJwksLoaderConfig;
            return this;
        }

        /**
         * Sets the file path for loading JWKS from a local file.
         * <p>
         * This method configures the issuer to load JWKS (JSON Web Key Set) from a local file.
         * This is useful for development environments, testing, or scenarios where JWKS are
         * distributed as part of the application deployment.
         * </p>
         * <p>
         * The file should contain a valid JWKS JSON structure with public keys only.
         * The file will be read during the first key access and cached in memory.
         * </p>
         * <p>
         * Example usage:
         * <pre>
         * // Absolute path
         * builder.jwksFilePath("/etc/security/jwks.json");
         *
         * // Relative path (relative to application working directory)
         * builder.jwksFilePath("config/jwks.json");
         *
         * // Classpath resource (if using resource loading utilities)
         * builder.jwksFilePath("classpath:jwks/public-keys.json");
         * </pre>
         * <p>
         * <strong>Required:</strong> When using file-based JWKS loading, the {@link #issuerIdentifier(String)}
         * must be explicitly provided as it cannot be determined from the file content.
         * </p>
         * <p>
         * <strong>Security Note:</strong> Ensure the JWKS file contains only public keys and is properly
         * secured with appropriate file system permissions.
         * </p>
         *
         * @param jwksFilePath the path to the JWKS file (absolute or relative)
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder jwksFilePath(String jwksFilePath) {
            this.jwksFilePath = jwksFilePath;
            return this;
        }

        /**
         * Sets the JWKS content directly as a JSON string.
         * <p>
         * This method configures the issuer to use JWKS (JSON Web Key Set) provided directly
         * as a JSON string. This is useful for testing, embedded configurations, or scenarios
         * where JWKS are generated or provided programmatically.
         * </p>
         * <p>
         * The content should be a valid JWKS JSON structure containing public keys only.
         * The content will be parsed during the first key access and cached in memory.
         * </p>
         * <p>
         * Example usage:
         * <pre>
         * String jwksJson = """{
         *   "keys": [
         *     {
         *       "kty": "RSA",
         *       "kid": "key-1",
         *       "n": "...",
         *       "e": "AQAB",
         *       "alg": "RS256"
         *     }
         *   ]
         * }""";
         *
         * builder.jwksContent(jwksJson);
         * </pre>
         * <p>
         * <strong>Required:</strong> When using in-memory JWKS content, the {@link #issuerIdentifier(String)}
         * must be explicitly provided as it cannot be determined from the content.
         * </p>
         * <p>
         * <strong>Security Note:</strong> Ensure the JWKS content contains only public keys and never
         * include private key material in the JWKS content.
         * </p>
         *
         * @param jwksContent the JWKS content as a JSON string
         * @return this builder instance for method chaining
         */
        public IssuerConfigBuilder jwksContent(String jwksContent) {
            this.jwksContent = jwksContent;
            return this;
        }

        /**
         * Builds and validates the IssuerConfig instance.
         * <p>
         * This method performs comprehensive validation of the configuration and creates the final
         * {@link IssuerConfig} instance. It ensures that all required fields are properly set
         * and that the configuration is internally consistent.
         * </p>
         * <p>
         * Validation includes:
         * <ul>
         *   <li><strong>JWKS Configuration:</strong> At least one JWKS loading method must be configured for enabled issuers</li>
         *   <li><strong>Issuer Identifier:</strong> Required for all enabled issuer configurations</li>
         *   <li><strong>Algorithm Preferences:</strong> Initialized with secure defaults if not explicitly set</li>
         *   <li><strong>Claim Mappers:</strong> Initialized as empty map if not explicitly set</li>
         * </ul>
         * <p>
         * The method automatically creates the appropriate {@link JwksLoader} based on the configuration:
         * <ol>
         *   <li>Custom {@link JwksLoader} (if provided via {@link #jwksLoader(JwksLoader)})</li>
         *   <li>HTTP-based loader (if {@link #httpJwksLoaderConfig(HttpJwksLoaderConfig)} is configured)</li>
         *   <li>File-based loader (if {@link #jwksFilePath(String)} is configured)</li>
         *   <li>In-memory loader (if {@link #jwksContent(String)} is configured)</li>
         * </ol>
         *
         * @return a fully configured and validated {@link IssuerConfig} instance
         * @throws IllegalArgumentException if the configuration is invalid or incomplete
         */
        public IssuerConfig build() {
            // If enabled, validate and create JwksLoader if needed
            if (enabled) {
                validateConfiguration();
                createJwksLoaderIfNeeded();

                // Validate audience configuration: either set expectedAudience or explicitly disable
                if (!audienceValidationDisabled
                        && (expectedAudience == null || expectedAudience.isEmpty())) {
                    throw new IllegalArgumentException(
                            "expectedAudience must be non-empty for issuer '%s'. "
                                    .formatted(issuerIdentifier != null ? issuerIdentifier : "unknown")
                                    + "Either configure expected audience values or set audienceValidationDisabled(true).");
                }
            }

            // Warn about RFC compliance when subject claim is made optional
            if (claimSubOptional) {
                LOGGER.warn(JWTValidationLogMessages.WARN.CLAIM_SUB_OPTIONAL_WARNING, issuerIdentifier != null ? issuerIdentifier : "unknown");
            }

            return new IssuerConfig(enabled, issuerIdentifier,
                    expectedAudience != null ? expectedAudience : Set.of(),
                    audienceValidationDisabled,
                    expectedClientId != null ? expectedClientId : Set.of(),
                    claimSubOptional, accessTokenAudienceOptional,
                    azpAudienceFallbackEnabled, clientIdFallbackEnabled, expectedTokenType,
                    dpopConfig, clockSkewSeconds, maxTokenAgeSeconds, algorithmPreferences,
                    claimMappers != null ? claimMappers : Map.of(), jwksLoader);
        }

        private void validateConfiguration() {
            // Validate that at least one JWKS loading method is configured
            if (httpJwksLoaderConfig == null && jwksFilePath == null &&
                    jwksContent == null && jwksLoader == null) {
                throw new IllegalArgumentException("""
                        No JwksLoader configuration is present for enabled issuer. \
                        One of httpJwksLoaderConfig, jwksFilePath, jwksContent, or a custom jwksLoader must be provided.""");
            }

            // issuerIdentifier is required for every enabled configuration, regardless of
            // the JWKS loading method. Validator maps and caches are keyed by this value
            // before any (async) JWKS loading has completed, so it cannot be supplied by
            // well-known discovery.
            if (issuerIdentifier == null || issuerIdentifier.isBlank()) {
                throw new IllegalArgumentException("""
                        issuerIdentifier is required (non-blank) for enabled issuer configurations. \
                        For well-known discovery, set it to the issuer URL of the discovery document.""");
            }
        }

        private void createJwksLoaderIfNeeded() {
            if (jwksLoader == null) {
                // Create JwksLoader based on the first available configuration
                // SecurityEventCounter will be set later via initJWKSLoader()
                if (httpJwksLoaderConfig != null) {
                    jwksLoader = JwksLoaderFactory.createHttpLoader(httpJwksLoaderConfig);
                } else if (jwksFilePath != null) {
                    jwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath);
                } else if (jwksContent != null) {
                    jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
                }
            }
        }
    }

    /**
     * Constructor for the validated IssuerConfig.
     * This is called only by the builder after validation.
     */
    @SuppressWarnings("java:S107") // ok for private constructor
    private IssuerConfig(boolean enabled, @Nullable String issuerIdentifier, Set<String> expectedAudience,
            boolean audienceValidationDisabled, Set<String> expectedClientId,
            boolean claimSubOptional, boolean accessTokenAudienceOptional,
            boolean azpAudienceFallbackEnabled, boolean clientIdFallbackEnabled, @Nullable String expectedTokenType,
            @Nullable DpopConfig dpopConfig, int clockSkewSeconds, @Nullable Integer maxTokenAgeSeconds,
            SignatureAlgorithmPreferences algorithmPreferences,
            Map<String, ClaimMapper> claimMappers, @Nullable JwksLoader jwksLoader) {
        this.enabled = enabled;
        this.issuerIdentifier = issuerIdentifier;
        this.expectedAudience = Set.copyOf(Objects.requireNonNull(expectedAudience, "expectedAudience must not be null (use Set.of() for empty)"));
        this.audienceValidationDisabled = audienceValidationDisabled;
        this.expectedClientId = Set.copyOf(Objects.requireNonNull(expectedClientId, "expectedClientId must not be null (use Set.of() for empty)"));
        this.claimSubOptional = claimSubOptional;
        this.accessTokenAudienceOptional = accessTokenAudienceOptional;
        this.azpAudienceFallbackEnabled = azpAudienceFallbackEnabled;
        this.clientIdFallbackEnabled = clientIdFallbackEnabled;
        this.expectedTokenType = expectedTokenType;
        this.dpopConfig = dpopConfig;
        this.clockSkewSeconds = clockSkewSeconds;
        this.maxTokenAgeSeconds = maxTokenAgeSeconds;
        this.algorithmPreferences = Objects.requireNonNull(algorithmPreferences, "algorithmPreferences must not be null");
        this.claimMappers = Map.copyOf(Objects.requireNonNull(claimMappers, "claimMappers must not be null (use Map.of() for empty)"));
        this.jwksLoader = jwksLoader;
    }

}
