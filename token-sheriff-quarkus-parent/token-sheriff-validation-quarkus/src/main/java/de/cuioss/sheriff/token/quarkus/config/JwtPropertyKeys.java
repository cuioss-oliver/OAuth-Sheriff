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

import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import lombok.experimental.UtilityClass;

/**
 * Constants for JWT property keys used in the Token-Sheriff Quarkus module.
 * <p>
 * This class follows the DSL-style nested constants pattern to organize
 * property keys in a hierarchical, discoverable manner.
 * </p>
 * <p>
 * All properties are prefixed with "sheriff.token".
 * </p>
 *
 * @since 1.0
 */
@UtilityClass
public final class JwtPropertyKeys {

    /**
     * The common prefix for all JWT properties.
     */
    public static final String PREFIX = "sheriff.token";
    public static final String DOT_JWKS = ".jwks";
    public static final String DOT_ENABLED = ".enabled";

    /**
     * Properties related to JWT parser configuration.
     */
    @UtilityClass
    public static final class PARSER {
        /**
         * Base path for parser configurations.
         */
        public static final String BASE = PREFIX + ".parser";

        /**
         * Maximum size of a JWT token in bytes to prevent overflow attacks.
         */
        public static final String MAX_TOKEN_SIZE = BASE + ".max-token-size";

        /**
         * Maximum size of decoded JSON payload in bytes.
         */
        public static final String MAX_PAYLOAD_SIZE = BASE + ".max-payload-size";

        /**
         * Maximum string length for JSON parsing in bytes.
         */
        public static final String MAX_STRING_LENGTH = BASE + ".max-string-length";

    }

    /**
     * Properties related to JWT issuers configuration.
     * <p>
     * These keys use a template system for dynamic issuer configuration.
     * Usage pattern: KEY.formatted("issuerName") where "issuerName" is an arbitrary string.
     * </p>
     * <p>
     * Example: ENABLED.formatted("default") -> "sheriff.token.issuers.default.enabled"
     * </p>
     * <p>
     * <strong>JWKS Source Configuration (Mutually Exclusive):</strong>
     * Only one JWKS source may be configured per issuer:
     * <ul>
     *   <li>{@link #JWKS_URL} - Direct JWKS endpoint (requires {@link #ISSUER_IDENTIFIER})</li>
     *   <li>{@link #WELL_KNOWN_URL} - Well-known discovery (provides issuer identifier automatically)</li>
     *   <li>{@link #JWKS_FILE_PATH} - Local file (requires {@link #ISSUER_IDENTIFIER})</li>
     *   <li>{@link #JWKS_CONTENT} - Inline content (requires {@link #ISSUER_IDENTIFIER})</li>
     * </ul>
     */
    @UtilityClass
    public static final class ISSUERS {
        /**
         * Base template for issuer configurations.
         */
        public static final String BASE = PREFIX + ".issuers.%s.";

        /**
         * Base template for JWKS configurations.
         */
        public static final String JWKS_BASE = BASE + "jwks.";

        /**
         * Base template for HTTP configurations.
         */
        public static final String HTTP_BASE = JWKS_BASE + "http.";

        // === Core Configuration ===

        /**
         * Whether this issuer configuration is enabled.
         * Template: "sheriff.token.issuers.%s.enabled"
         * <p>
         * When set to {@code false}, this issuer configuration will be ignored during
         * token validation and will not attempt to use the underlying {@link JwksLoader}.
         * This allows for easy enabling/disabling of specific issuers without removing
         * their configuration.
         * Default value is {@code false}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String ENABLED = BASE + "enabled";

        /**
         * The issuer identifier that will be matched against the "iss" claim in JWT tokens.
         * Template: "sheriff.token.issuers.%s.issuer-identifier"
         * <p>
         * This field is required for all JWKS loading variants except well-known discovery.
         * For well-known discovery, the issuer identifier is automatically extracted from
         * the discovery document and this field is optional.
         * This identifier must match the "iss" claim in validated tokens.
         * </p>
         * <p>
         * <strong>Required</strong> for {@link #JWKS_URL}, {@link #JWKS_FILE_PATH}, and {@link #JWKS_CONTENT}.
         * <strong>Optional</strong> for {@link #WELL_KNOWN_URL} (extracted from discovery document).
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String ISSUER_IDENTIFIER = BASE + "issuer-identifier";

        /**
         * Set of expected audience values (comma-separated).
         * Template: "sheriff.token.issuers.%s.expected-audience"
         * <p>
         * These values are matched against the "aud" claim in the token.
         * If the token's audience claim matches any of these values, it is considered valid.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String EXPECTED_AUDIENCE = BASE + "expected-audience";

        /**
         * Explicitly disable audience validation for this issuer.
         * Template: "sheriff.token.issuers.%s.audience-validation-disabled"
         */
        public static final String AUDIENCE_VALIDATION_DISABLED = BASE + "audience-validation-disabled";

        /**
         * Set of expected client ID values (comma-separated).
         * Template: "sheriff.token.issuers.%s.expected-client-id"
         * <p>
         * These values are matched against the "azp" or "client_id" claim in the token.
         * If the token's client ID claim matches any of these values, it is considered valid.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String EXPECTED_CLIENT_ID = BASE + "expected-client-id";

        /**
         * Signature algorithm preferences (comma-separated).
         * Template: "sheriff.token.issuers.%s.algorithm-preferences"
         * <p>
         * This configuration controls which signature algorithms are preferred and allowed
         * during token validation. It can be used to enforce security policies, such as
         * requiring stronger algorithms or blacklisting weak ones.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String ALGORITHM_PREFERENCES = BASE + "algorithm-preferences";

        /**
         * Whether the "sub" (subject) claim is optional for this issuer.
         * Template: "sheriff.token.issuers.%s.claim-sub-optional"
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
         * @see de.cuioss.sheriff.token.validation.IssuerConfig#isClaimSubOptional()
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
         */
        public static final String CLAIM_SUB_OPTIONAL = BASE + "claim-sub-optional";

        /**
         * Whether the audience claim is optional for access tokens from this issuer.
         * Template: "sheriff.token.issuers.%s.access-token-audience-optional"
         * <p>
         * Default value is {@code false} (audience claim is required for access tokens
         * when expected-audience is configured).
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig#isAccessTokenAudienceOptional()
         */
        public static final String ACCESS_TOKEN_AUDIENCE_OPTIONAL = BASE + "access-token-audience-optional";

        /**
         * Expected JWT "typ" header value for this issuer (e.g., "at+jwt").
         * Template: "sheriff.token.issuers.%s.expected-token-type"
         * <p>
         * When configured, tokens with a missing or mismatched "typ" header will be rejected.
         * When not set (default), no token type validation is performed.
         * </p>
         * <p>
         * <strong>Security recommendation:</strong> Set to {@code "at+jwt"} if your IdP issues
         * RFC 9068-compliant tokens to prevent token type confusion attacks.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068</a>
         * @see de.cuioss.sheriff.token.validation.IssuerConfig#getExpectedTokenType()
         */
        public static final String EXPECTED_TOKEN_TYPE = BASE + "expected-token-type";

        /**
         * Clock skew tolerance in seconds for time-based claim validation (exp, nbf).
         * Template: "sheriff.token.issuers.%s.clock-skew-seconds"
         * <p>
         * Accommodates clock drift between the token issuer and the validator in distributed systems.
         * A token is considered expired only when {@code exp + clockSkewSeconds < now}.
         * </p>
         * <p>
         * Default value is {@code 60} seconds.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig#getClockSkewSeconds()
         * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.clock.skew</a>
         */
        public static final String CLOCK_SKEW_SECONDS = BASE + "clock-skew-seconds";

        /**
         * Maximum token age in seconds based on the {@code iat} claim.
         * Template: "sheriff.token.issuers.%s.max-token-age-seconds"
         * <p>
         * When set, tokens where {@code now - iat > maxTokenAgeSeconds + clockSkewSeconds}
         * are rejected, even if not yet expired.
         * </p>
         * <p>
         * Default value is disabled (no maximum token age enforcement).
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig#getMaxTokenAgeSeconds()
         * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.token.age</a>
         */
        public static final String MAX_TOKEN_AGE_SECONDS = BASE + "max-token-age-seconds";

        // === DPoP Configuration (RFC 9449) ===

        /**
         * Base template for DPoP configurations.
         */
        public static final String DPOP_BASE = BASE + "dpop.";

        /**
         * Whether DPoP validation is enabled for this issuer.
         * Template: "sheriff.token.issuers.%s.dpop.enabled"
         * <p>
         * When set to {@code true}, DPoP validation per RFC 9449 is activated.
         * Tokens with a {@code cnf.jkt} claim will be validated against a DPoP proof JWT.
         * </p>
         * <p>
         * Default value is {@code false}.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449</a>
         */
        public static final String DPOP_ENABLED = DPOP_BASE + "enabled";

        /**
         * Whether DPoP is required for all tokens from this issuer.
         * Template: "sheriff.token.issuers.%s.dpop.required"
         * <p>
         * When {@code true}, tokens without a {@code cnf.jkt} claim are rejected.
         * When {@code false} (default), tokens without {@code cnf.jkt} pass normally (bearer mode).
         * </p>
         */
        public static final String DPOP_REQUIRED = DPOP_BASE + "required";

        /**
         * Maximum age in seconds for DPoP proof {@code iat} claims.
         * Template: "sheriff.token.issuers.%s.dpop.proof-max-age-seconds"
         * <p>
         * Default value is {@code 300} (5 minutes).
         * </p>
         */
        public static final String DPOP_PROOF_MAX_AGE_SECONDS = DPOP_BASE + "proof-max-age-seconds";

        /**
         * Maximum number of jti entries in the DPoP replay protection cache.
         * Template: "sheriff.token.issuers.%s.dpop.nonce-cache-size"
         * <p>
         * Default value is {@code 10000}.
         * </p>
         */
        public static final String DPOP_NONCE_CACHE_SIZE = DPOP_BASE + "nonce-cache-size";

        /**
         * Time-to-live in seconds for jti entries in the DPoP replay cache.
         * Template: "sheriff.token.issuers.%s.dpop.nonce-cache-ttl-seconds"
         * <p>
         * Default value is {@code 300} (5 minutes).
         * </p>
         */
        public static final String DPOP_NONCE_CACHE_TTL_SECONDS = DPOP_BASE + "nonce-cache-ttl-seconds";

        // === JWKS Source Configuration (Mutually Exclusive) ===

        /**
         * The URL of the JWKS endpoint for direct loading.
         * Template: "sheriff.token.issuers.%s.jwks.http.url"
         * <p>
         * This method configures the issuer to load JWKS (JSON Web Key Set) from a remote HTTP endpoint.
         * This is the most common configuration for production environments where JWKS are served
         * by an identity provider or authorization server.
         * </p>
         * <p>
         * <strong>Mutually exclusive</strong> with {@link #WELL_KNOWN_URL}, {@link #JWKS_FILE_PATH}, and {@link #JWKS_CONTENT}.
         * <strong>Requires</strong> {@link #ISSUER_IDENTIFIER}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig
         */
        public static final String JWKS_URL = HTTP_BASE + "url";

        /**
         * The URL of the OpenID Connect discovery document (well-known endpoint).
         * Template: "sheriff.token.issuers.%s.jwks.http.well-known-url"
         * <p>
         * This method configures the JWKS loading using well-known endpoint discovery from a URL string.
         * This method creates a WellKnownConfig internally for dynamic JWKS URI resolution.
         * The JWKS URI will be extracted at runtime from the well-known discovery document.
         * </p>
         * <p>
         * <strong>Mutually exclusive</strong> with {@link #JWKS_URL}, {@link #JWKS_FILE_PATH}, and {@link #JWKS_CONTENT}.
         * Provides {@link #ISSUER_IDENTIFIER} automatically from discovery document.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig
         */
        public static final String WELL_KNOWN_URL = HTTP_BASE + "well-known-url";

        /**
         * File path for loading JWKS from a local file.
         * Template: "sheriff.token.issuers.%s.jwks.file-path"
         * <p>
         * This method configures the issuer to load JWKS (JSON Web Key Set) from a local file.
         * This is useful for development environments, testing, or scenarios where JWKS are
         * distributed as part of the application deployment.
         * The file should contain a valid JWKS JSON structure with public keys only.
         * </p>
         * <p>
         * <strong>Mutually exclusive</strong> with {@link #JWKS_URL}, {@link #WELL_KNOWN_URL}, and {@link #JWKS_CONTENT}.
         * <strong>Requires</strong> {@link #ISSUER_IDENTIFIER}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String JWKS_FILE_PATH = JWKS_BASE + "file-path";

        /**
         * JWKS content directly as a JSON string.
         * Template: "sheriff.token.issuers.%s.jwks.content"
         * <p>
         * This method configures the issuer to use JWKS (JSON Web Key Set) provided directly
         * as a JSON string. This is useful for testing, embedded configurations, or scenarios
         * where JWKS are generated or provided programmatically.
         * The content should be a valid JWKS JSON structure containing public keys only.
         * </p>
         * <p>
         * <strong>Mutually exclusive</strong> with {@link #JWKS_URL}, {@link #WELL_KNOWN_URL}, and {@link #JWKS_FILE_PATH}.
         * <strong>Requires</strong> {@link #ISSUER_IDENTIFIER}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.IssuerConfig
         */
        public static final String JWKS_CONTENT = JWKS_BASE + "content";

        // === HTTP Configuration (Only for JWKS_URL and WELL_KNOWN_URL) ===

        /**
         * The refresh interval in seconds for HTTP-based JWKS loading.
         * Template: "sheriff.token.issuers.%s.jwks.http.refresh-interval-seconds"
         * <p>
         * The interval in seconds at which to refresh the keys.
         * If set to 0, no time-based caching will be used.
         * It defaults to 10 minutes (600 seconds).
         * </p>
         * <p>
         * <strong>Only applicable</strong> for {@link #JWKS_URL} and {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig
         */
        public static final String REFRESH_INTERVAL_SECONDS = HTTP_BASE + "refresh-interval-seconds";

        /**
         * The connection timeout in seconds for HTTP requests.
         * Template: "sheriff.token.issuers.%s.jwks.http.connect-timeout-seconds"
         * <p>
         * Sets the connection timeout in seconds for HTTP requests to JWKS endpoints.
         * This timeout controls how long to wait when establishing a connection to the remote server.
         * </p>
         * <p>
         * <strong>Only applicable</strong> for {@link #JWKS_URL} and {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig
         */
        public static final String CONNECT_TIMEOUT_SECONDS = HTTP_BASE + "connect-timeout-seconds";

        /**
         * The read timeout in seconds for HTTP requests.
         * Template: "sheriff.token.issuers.%s.jwks.http.read-timeout-seconds"
         * <p>
         * Sets the read timeout in seconds for HTTP requests to JWKS endpoints.
         * This timeout controls how long to wait for data to be received from the remote server
         * after the connection has been established.
         * </p>
         * <p>
         * <strong>Only applicable</strong> for {@link #JWKS_URL} and {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig
         */
        public static final String READ_TIMEOUT_SECONDS = HTTP_BASE + "read-timeout-seconds";

        /**
         * The grace period in seconds for retired keys during rotation.
         * Template: "sheriff.token.issuers.%s.jwks.http.key-rotation-grace-period-seconds"
         * <p>
         * Sets the grace period for which retired keys remain valid after key rotation.
         * During this period, tokens signed with recently rotated keys can still be validated,
         * preventing service disruptions for in-flight requests. Set to 0 to immediately
         * invalidate old keys upon rotation.
         * </p>
         * <p>
         * Default value is {@code 300} (5 minutes).
         * </p>
         * <p>
         * <strong>Only applicable</strong> for {@link #JWKS_URL} and {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see HttpJwksLoaderConfig#getKeyRotationGracePeriod()
         * @see <a href="https://github.com/cuioss/TokenSheriff/issues/110">Issue #110: Key rotation grace period</a>
         */
        public static final String KEY_ROTATION_GRACE_PERIOD_SECONDS = HTTP_BASE + "key-rotation-grace-period-seconds";

        /**
         * The maximum number of retired key sets to retain.
         * Template: "sheriff.token.issuers.%s.jwks.http.max-retired-key-sets"
         * <p>
         * Sets the maximum number of retired key sets to keep in memory during the grace period.
         * This prevents unbounded memory growth when keys rotate frequently. Older retired
         * key sets beyond this limit are removed even if still within the grace period.
         * </p>
         * <p>
         * Default value is {@code 3}.
         * </p>
         * <p>
         * <strong>Only applicable</strong> for {@link #JWKS_URL} and {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig#getMaxRetiredKeySets()
         * @see <a href="https://github.com/cuioss/TokenSheriff/issues/110">Issue #110: Key rotation grace period</a>
         */
        public static final String MAX_RETIRED_KEY_SETS = HTTP_BASE + "max-retired-key-sets";

        /**
         * Whether cleartext {@code http://} JWKS and well-known discovery URLs are permitted for this issuer.
         * Template: "sheriff.token.issuers.%s.jwks.http.allow-insecure-http"
         * <p>
         * By default, the transport layer requires {@code https://} for JWKS and well-known discovery
         * fetches and rejects cleartext {@code http://} URLs. Setting this to {@code true} opts into
         * cleartext transport, which is only appropriate for local development and integration tests
         * (for example, a Keycloak reached over {@code http://localhost}).
         * </p>
         * <p>
         * <strong>Security warning:</strong> Never enable this in production. Cleartext transport exposes
         * JWKS material and discovery documents to interception and tampering.
         * </p>
         * <p>
         * Default value is {@code false} (HTTPS required). Applies to both {@link #JWKS_URL} and
         * {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder#allowInsecureHttp(boolean)
         */
        public static final String ALLOW_INSECURE_HTTP = HTTP_BASE + "allow-insecure-http";

        /**
         * Whether egress to loopback/link-local/site-local/ULA/metadata addresses is permitted for this issuer.
         * Template: "sheriff.token.issuers.%s.jwks.http.allow-loopback-egress"
         * <p>
         * By default, the transport layer's egress guard rejects JWKS and well-known discovery fetches
         * whose host resolves to a loopback, link-local, site-local, unique-local, or cloud-metadata
         * address, mitigating SSRF. Setting this to {@code true} opts into loopback egress, which is
         * only appropriate for local development and integration tests (for example, a Keycloak reached
         * over {@code http://localhost}).
         * </p>
         * <p>
         * <strong>Security warning:</strong> Never enable this in production. It weakens the SSRF egress
         * guard on both the advertised JWKS URI and the well-known discovery fetch.
         * </p>
         * <p>
         * Default value is {@code false} (loopback egress rejected). Applies to both {@link #JWKS_URL} and
         * {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder#allowLoopbackEgress(boolean)
         */
        public static final String ALLOW_LOOPBACK_EGRESS = HTTP_BASE + "allow-loopback-egress";

        /**
         * Comma-separated list of hosts to add to the SSRF egress guard's explicit allow-list for this issuer.
         * Template: "sheriff.token.issuers.%s.jwks.http.allowed-egress-hosts"
         * <p>
         * Allow-listed hosts bypass the egress guard's address-range checks entirely, so a JWKS or
         * well-known discovery endpoint whose host resolves to a site-local, link-local, or ULA address
         * (for example a Docker service name such as {@code keycloak} on a container bridge network) can
         * be reached despite the secure-by-default egress policy. Matching is case-insensitive.
         * </p>
         * <p>
         * Unlike {@link #ALLOW_LOOPBACK_EGRESS} — which only permits {@code 127.0.0.0/8} / {@code ::1}
         * loopback resolutions — this allow-list is the mechanism for reaching Docker-internal service
         * names whose bridge-network addresses fall in the private (site-local) ranges.
         * </p>
         * <p>
         * <strong>Security warning:</strong> Never allow-list attacker-influenceable hosts in production.
         * Scope this narrowly to trusted local/dev and integration-test topologies.
         * </p>
         * <p>
         * Default value is empty (no host allow-listed). Applies to both {@link #JWKS_URL} and
         * {@link #WELL_KNOWN_URL}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder#allowedEgressHost(String)
         */
        public static final String ALLOWED_EGRESS_HOSTS = HTTP_BASE + "allowed-egress-hosts";

    }

    /**
     * Properties related to token extraction configuration.
     * <p>
     * These properties control how tokens are extracted from HTTP requests.
     * By default, tokens are extracted from the Authorization header.
     * When configured for cookie-based extraction, tokens are read from
     * a named HTTP cookie instead.
     * </p>
     * <p>
     * All properties are prefixed with "sheriff.token.token".
     * </p>
     *
     * @since 1.0
     */
    @UtilityClass
    public static final class TOKEN {
        private static final String BASE = PREFIX + ".token";

        /**
         * The HTTP header to extract the token from.
         * Property: "sheriff.token.token.header"
         * <p>
         * Supported values:
         * <ul>
         *   <li>{@code Authorization} (default) - standard Bearer token from Authorization header</li>
         *   <li>{@code Cookie} - extract token from a named HTTP cookie</li>
         * </ul>
         */
        public static final String HEADER = BASE + ".header";

        /**
         * The cookie name to extract the token from when header is set to Cookie.
         * Property: "sheriff.token.token.cookie-name"
         * <p>
         * Default value is {@code Bearer}.
         * </p>
         */
        public static final String COOKIE_NAME = BASE + ".cookie-name";
    }

    /**
     * Global Keycloak mapper configuration properties.
     * <p>
     * These properties control the activation of built-in Keycloak claim mappers
     * globally across all configured issuers. The mappers are registered as CDI beans
     * and discovered by the {@link de.cuioss.sheriff.token.quarkus.mapper.ClaimMapperRegistry}.
     * </p>
     * <p>
     * All properties are prefixed with "sheriff.token.keycloak".
     * </p>
     *
     */
    @UtilityClass
    public static final class KEYCLOAK {
        /**
         * Base path for global Keycloak configurations.
         */
        public static final String BASE = PREFIX + ".keycloak";

        /**
         * Enable the Keycloak default roles mapper globally.
         * Property: "sheriff.token.keycloak.default-roles-mapper.enabled"
         * <p>
         * When enabled, the {@link de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultRolesMapper}
         * is registered as a CDI bean and applied to all configured issuers.
         * It maps Keycloak's {@code realm_access.roles} to the {@code roles} claim.
         * </p>
         * <p>
         * Default value is {@code false}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultRolesMapper
         */
        public static final String DEFAULT_ROLES_MAPPER_ENABLED = BASE + ".default-roles-mapper.enabled";

        /**
         * Enable the Keycloak default groups mapper globally.
         * Property: "sheriff.token.keycloak.default-groups-mapper.enabled"
         * <p>
         * When enabled, the {@link de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultGroupsMapper}
         * is registered as a CDI bean and applied to all configured issuers.
         * It processes Keycloak's standard {@code groups} claim.
         * </p>
         * <p>
         * Default value is {@code false}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultGroupsMapper
         */
        public static final String DEFAULT_GROUPS_MAPPER_ENABLED = BASE + ".default-groups-mapper.enabled";
    }

    /**
     * Properties related to health checks.
     */
    @UtilityClass
    public static final class HEALTH {
        /**
         * Base path for health check configurations.
         */
        public static final String BASE = PREFIX + ".health";

        /**
         * Properties related to JWKS endpoint health checks.
         */
        @UtilityClass
        public static final class JWKS {
            /**
             * Base path for JWKS health check configurations.
             */
            public static final String BASE = HEALTH.BASE + DOT_JWKS;

            /**
             * The cache time-to-live in seconds for health check results.
             */
            public static final String CACHE_SECONDS = BASE + ".cache-seconds";

        }
    }

    /**
     * Interval for metrics collection in seconds.
     * Property: "sheriff.token.metrics.collection.interval"
     * <p>
     * Controls how frequently the {@link de.cuioss.sheriff.token.quarkus.metrics.JwtMetricsCollector}
     * updates Micrometer metrics from the internal counters and monitors.
     * </p>
     * <p>
     * Default value is {@code 10s} for production environments.
     * For integration tests, this can be set to {@code 2s} for faster testing.
     * </p>
     */
    public static final String METRICS_COLLECTION_INTERVAL = PREFIX + ".metrics.collection.interval";

    /**
     * Properties related to HTTP access log filtering configuration.
     * <p>
     * These properties control the custom access log filter that provides
     * more granular logging control than Quarkus built-in access logging.
     * The filter is controlled by DEBUG log level and can filter by status codes and paths.
     * </p>
     * <p>
     * All properties are prefixed with "cui.http.access-log.filter".
     * Control via log level: quarkus.log.category."cui.http.access-log.filter".level=DEBUG
     * </p>
     */
    @UtilityClass
    public static final class ACCESSLOG {
        /**
         * Base path for access log filter configurations.
         */
        public static final String BASE = "cui.http.access-log.filter";

        /**
         * Minimum HTTP status code to log.
         * Template: "cui.http.access-log.filter.min-status-code"
         * <p>
         * Only responses with status codes >= this value will be logged.
         * Common values:
         * - 200: Log all responses (equivalent to standard access log)
         * - 400: Log only client and server errors (default)
         * - 500: Log only server errors
         * </p>
         * <p>
         * Default value is {@code 400}.
         * </p>
         */
        public static final String MIN_STATUS_CODE = BASE + ".min-status-code";

        /**
         * Maximum HTTP status code to log.
         * Template: "cui.http.access-log.filter.max-status-code"
         * <p>
         * Only responses with status codes {@code <=} this value will be logged.
         * Set to 599 to include all error codes.
         * </p>
         * <p>
         * Default value is {@code 599}.
         * </p>
         */
        public static final String MAX_STATUS_CODE = BASE + ".max-status-code";

        /**
         * Specific HTTP status codes to always log (comma-separated).
         * Template: "cui.http.access-log.filter.include-status-codes"
         * <p>
         * These status codes will be logged regardless of min/max range.
         * Useful for logging specific success codes (like 201, 202) along with errors.
         * </p>
         * <p>
         * Example: "201,202,204" to log created and accepted responses.
         * </p>
         */
        public static final String INCLUDE_STATUS_CODES = BASE + ".include-status-codes";

        /**
         * URL path patterns to include in logging (comma-separated).
         * Template: "cui.http.access-log.filter.include-paths"
         * <p>
         * If specified, only requests matching these patterns will be considered for logging.
         * Uses simple glob patterns (* and **).
         * Empty list means all paths are eligible.
         * </p>
         * <p>
         * Example: "/api/**,/health/**" to log only API and health endpoints.
         * </p>
         */
        public static final String INCLUDE_PATHS = BASE + ".include-paths";

        /**
         * URL path patterns to exclude from logging (comma-separated).
         * Template: "cui.http.access-log.filter.exclude-paths"
         * <p>
         * These patterns override include patterns.
         * Uses simple glob patterns (* and **).
         * Common exclusions: /health/*, /metrics/*, /jwt/validate
         * </p>
         * <p>
         * Example: "/health/**,/metrics/**" to exclude health and metrics endpoints.
         * </p>
         */
        public static final String EXCLUDE_PATHS = BASE + ".exclude-paths";

        /**
         * Log format pattern.
         * Template: "cui.http.access-log.filter.pattern"
         * <p>
         * Supports placeholders:
         * - {method}: HTTP method (GET, POST, etc.)
         * - {path}: Request path
         * - {status}: HTTP status code
         * - {duration}: Request duration in milliseconds
         * - {remoteAddr}: Remote IP address
         * - {userAgent}: User-Agent header
         * </p>
         * <p>
         * Default pattern: "{remoteAddr} {method} {path} -> {status} ({duration}ms)"
         * </p>
         */
        public static final String PATTERN = BASE + ".pattern";

        /**
         * Whether the access log filter is enabled.
         * Template: "cui.http.access-log.filter.enabled"
         * <p>
         * When set to true, the access log filter will process HTTP requests and responses
         * according to the configured filtering rules. When false, the filter is disabled
         * and no access logging will occur.
         * </p>
         * <p>
         * Default value is {@code false}.
         * </p>
         */
        public static final String ENABLED = BASE + DOT_ENABLED;
    }

    /**
     * Properties related to JWE (JSON Web Encryption) decryption configuration.
     * <p>
     * These properties configure JWE token decryption at the TokenValidator level
     * (not per-issuer), because the decryption private key belongs to this Resource Server.
     * </p>
     */
    @UtilityClass
    public static final class JWE {
        /**
         * Base path for JWE configurations.
         */
        public static final String BASE = PREFIX + ".jwe";

        /**
         * Path to a PKCS#8 PEM file containing the decryption private key.
         * Property: "sheriff.token.jwe.decryption-key-path"
         */
        public static final String DECRYPTION_KEY_PATH = BASE + ".decryption-key-path";

        /**
         * Key ID for the single decryption key.
         * Property: "sheriff.token.jwe.decryption-key-id"
         */
        public static final String DECRYPTION_KEY_ID = BASE + ".decryption-key-id";

        /**
         * Path to a keystore (JKS or PKCS#12) containing the decryption key.
         * Property: "sheriff.token.jwe.keystore-path"
         */
        public static final String KEYSTORE_PATH = BASE + ".keystore-path";

        /**
         * Keystore password.
         * Property: "sheriff.token.jwe.keystore-password"
         */
        public static final String KEYSTORE_PASSWORD = BASE + ".keystore-password";

        /**
         * Alias of the key entry in the keystore.
         * Property: "sheriff.token.jwe.key-alias"
         */
        public static final String KEY_ALIAS = BASE + ".key-alias";

        /**
         * Key entry password in the keystore.
         * Property: "sheriff.token.jwe.key-password"
         */
        public static final String KEY_PASSWORD = BASE + ".key-password";

        /**
         * Prefix for multiple decryption keys for rotation support.
         * Pattern: "sheriff.token.jwe.decryption-keys.{kid}.path"
         */
        public static final String MULTI_KEY_PREFIX = BASE + ".decryption-keys.";

        /**
         * Default key ID when multiple keys are configured.
         * Property: "sheriff.token.jwe.default-key-id"
         */
        public static final String DEFAULT_KEY_ID = BASE + ".default-key-id";

        /**
         * Comma-separated list of allowed key management algorithms.
         * Property: "sheriff.token.jwe.key-management-algorithms"
         * <p>
         * Default: RSA-OAEP, RSA-OAEP-256, ECDH-ES
         */
        public static final String KEY_MANAGEMENT_ALGORITHMS = BASE + ".key-management-algorithms";

        /**
         * Comma-separated list of allowed content encryption algorithms.
         * Property: "sheriff.token.jwe.content-encryption-algorithms"
         * <p>
         * Default: A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512
         */
        public static final String CONTENT_ENCRYPTION_ALGORITHMS = BASE + ".content-encryption-algorithms";

        /**
         * Maximum size of encrypted JWE tokens in bytes.
         * Property: "sheriff.token.jwe.max-encrypted-token-size"
         * <p>
         * Default: 32768 (32 KB)
         */
        public static final String MAX_ENCRYPTED_TOKEN_SIZE = BASE + ".max-encrypted-token-size";
    }

    /**
     * Properties related to HTTP retry configuration.
     */
    @UtilityClass
    public static final class RETRY {
        private static final String PREFIX_RETRY = PREFIX + ".retry";

        /**
         * Whether retry is enabled globally.
         * Default: true
         */
        public static final String ENABLED = PREFIX_RETRY + DOT_ENABLED;

        /**
         * Maximum number of retry attempts.
         * Default: 5
         */
        public static final String MAX_ATTEMPTS = PREFIX_RETRY + ".max-attempts";

        /**
         * Initial retry delay in milliseconds.
         * Default: 1000
         */
        public static final String INITIAL_DELAY_MS = PREFIX_RETRY + ".initial-delay-ms";

        /**
         * Maximum retry delay in milliseconds.
         * Default: 30000
         */
        public static final String MAX_DELAY_MS = PREFIX_RETRY + ".max-delay-ms";

        /**
         * Exponential backoff multiplier.
         * Default: 2.0
         */
        public static final String BACKOFF_MULTIPLIER = PREFIX_RETRY + ".backoff-multiplier";

        /**
         * Jitter factor for randomization.
         * Default: 0.1
         */
        public static final String JITTER_FACTOR = PREFIX_RETRY + ".jitter-factor";
    }

    /**
     * Properties related to access token caching configuration.
     */
    @UtilityClass
    public static final class CACHE {
        /**
         * Base path for cache configurations.
         */
        public static final String BASE = PREFIX + ".cache.access-token";

        /**
         * Maximum number of access tokens to cache.
         * Template: "sheriff.token.cache.access-token.max-size"
         * <p>
         * Controls the maximum number of validated access tokens that will be cached
         * to improve performance by avoiding redundant validations.
         * Set to 0 to disable caching completely.
         * </p>
         * <p>
         * Default value is {@code 1000}.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig
         */
        public static final String MAX_SIZE = BASE + ".max-size";

        /**
         * Interval in seconds between cache eviction runs.
         * Template: "sheriff.token.cache.access-token.eviction-interval-seconds"
         * <p>
         * Controls how frequently the cache checks for and removes expired tokens.
         * This helps maintain cache size and ensures expired tokens are not served
         * from the cache.
         * </p>
         * <p>
         * Default value is {@code 10} seconds.
         * </p>
         *
         * @see de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig
         */
        public static final String EVICTION_INTERVAL_SECONDS = BASE + ".eviction-interval-seconds";
    }

}
