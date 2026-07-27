/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.client.config;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;
import lombok.Value;
import org.jspecify.annotations.Nullable;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;

/**
 * Immutable configuration describing how this confidential client talks to a single
 * OpenID Connect / OAuth 2.0 authorization server (AS).
 * <p>
 * A {@code ClientConfiguration} is a value object: it is created once (typically at
 * application start) and then shared, read-only, across all concurrent flows for that
 * issuer. Immutability makes it inherently thread-safe (satisfying {@code CLIENT-22}) — no
 * flow can mutate shared client state, so there is no cross-flow interference over the
 * configuration.
 * <p>
 * Only the fields needed to bootstrap discovery and client authentication are modelled here;
 * flow-specific parameters (PKCE, {@code state}/{@code nonce}, DPoP keys) are created per flow
 * and are not part of the shared configuration.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@Value
@Builder
public class ClientConfiguration {

    /** Default TCP connect timeout, in seconds, when the caller does not override it. */
    public static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 5;

    /** Default response read timeout, in seconds, when the caller does not override it. */
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 10;

    /**
     * The authorization server's issuer identifier URL (for example
     * {@code https://issuer.example.com/realms/demo}). Discovery is performed against
     * {@code {issuer}/.well-known/openid-configuration}. Must not be {@code null}.
     */
    @NonNull
    String issuer;

    /**
     * The OAuth 2.0 {@code client_id} registered for this client at the AS. Must not be {@code null}.
     */
    @NonNull
    String clientId;

    /**
     * The client secret, used by the shared-secret authentication methods
     * ({@link ClientAuthMethod#CLIENT_SECRET_BASIC} / {@link ClientAuthMethod#CLIENT_SECRET_POST}).
     * {@code null} for the key-based methods ({@link ClientAuthMethod#PRIVATE_KEY_JWT} /
     * {@link ClientAuthMethod#TLS_CLIENT_AUTH}), where no shared secret exists. The secret is
     * never placed in a URL and never logged — excluded from the Lombok-generated
     * {@code toString()} so an incidental {@code toString()} of the whole configuration (a debug
     * log, an assertion failure message) can never leak it.
     */
    @Nullable
    @ToString.Exclude
    String clientSecret;

    /**
     * The client authentication method this client presents to the AS token endpoint. Must not
     * be {@code null}.
     */
    @NonNull
    ClientAuthMethod authMethod;

    /**
     * The OAuth 2.0 scopes this client requests, in request order. May be empty. The stored list
     * is immutable.
     */
    @Singular
    List<String> scopes;

    /**
     * The single, exact {@code redirect_uri} registered for the interactive
     * {@code authorization_code} flow, or {@code null} for non-interactive clients (for example a
     * pure {@code client_credentials} client). When present it is matched exactly — never by
     * prefix or pattern.
     */
    @Nullable
    String redirectUri;

    /**
     * Whether plaintext {@code http://} endpoints are permitted for discovery and back-channel
     * calls. Defaults to {@code false}, so a non-TLS issuer is rejected. Set to {@code true} only
     * for local test setups against a cleartext authorization server.
     */
    boolean allowInsecureHttp;

    /**
     * The TCP connect timeout, in seconds, applied to every outbound discovery and back-channel call.
     * Defaults to {@value #DEFAULT_CONNECT_TIMEOUT_SECONDS} seconds. Configurable so deployments behind
     * slow networks or in latency-sensitive paths can tune the transport rather than relying on a
     * hardcoded default (L15).
     */
    @Builder.Default
    int connectTimeoutSeconds = DEFAULT_CONNECT_TIMEOUT_SECONDS;

    /**
     * The response read timeout, in seconds, applied to every outbound discovery and back-channel call.
     * Defaults to {@value #DEFAULT_READ_TIMEOUT_SECONDS} seconds. Configurable for the same reason as
     * {@link #connectTimeoutSeconds} (L15).
     */
    @Builder.Default
    int readTimeoutSeconds = DEFAULT_READ_TIMEOUT_SECONDS;

    /**
     * The per-client outbound TLS trust material, applied to every discovery and back-channel call this
     * client issues, or {@code null} to use the cui-http / JVM default truststore (the behaviour when the
     * field is not configured).
     * <p>
     * This is the client-side analogue of {@code HttpJwksLoaderConfig.sslContext()} on the validation
     * side, and it is the supported way to trust a private-CA or self-signed authorization server: the
     * trust is scoped to this one client instead of being forced onto the whole JVM through a
     * process-global {@code javax.net.ssl.trustStore} override.
     * <p>
     * Excluded from {@code toString()} and from the generated {@code equals}/{@code hashCode} — an
     * {@link SSLContext} has identity semantics and no useful string form, mirroring how
     * {@code HttpJwksLoaderConfig} excludes its {@code HttpHandler}. Two configurations that differ only
     * in their {@code sslContext} therefore remain equal.
     * <p>
     * <strong>Reload consequence of that exclusion:</strong> a configuration diff cannot see a trust
     * rotation. Rebuilding this configuration with a new {@code SSLContext} and otherwise identical
     * values compares {@code equal} to the previous one, so the common
     * {@code if (!newConfig.equals(current)) rebuild()} reload idiom will not rebuild and the engine
     * keeps validating against the retired trust anchor until the process restarts. Trigger the rebuild
     * on the rotation event itself rather than on a configuration diff.
     * <p>
     * <strong>The supplied context MUST perform full certificate-chain validation.</strong> It is
     * applied verbatim — a trust-all {@code TrustManager} silently disables server authentication for
     * every credential-bearing back-channel request. This field narrows trust to a known CA; it is not
     * a mechanism for skipping verification.
     * <p>
     * <strong>Scope:</strong> this covers the calls the client engine issues (discovery, token,
     * userinfo, revocation, PAR). JWKS retrieval for token validation runs through
     * {@code HttpJwksLoaderConfig} and carries its own independent {@code sslContext()}, which must be
     * configured alongside this one against a private-CA authorization server.
     */
    @Nullable
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    SSLContext sslContext;

    /**
     * All-args constructor invoked by the Lombok-generated builder. It validates the configuration at
     * construction so a malformed client can never be built and later fail obscurely on the wire:
     * {@code issuer} and {@code clientId} must be non-blank, {@code issuer} must be a well-formed
     * absolute {@code http}/{@code https} URL with a host, and every {@code scope} must be non-blank
     * (a {@code null}/blank scope would otherwise serialise as the literal {@code "null"} in the
     * {@code scope} request parameter). This mirrors {@code PostLogoutRedirectValidator}, which
     * validates every entry it accepts (L14).
     *
     * @throws IllegalArgumentException if any field is blank, malformed, or otherwise invalid
     */
    // S107 (too many parameters) is unavoidable here: Lombok's @Builder generates a call to this
    // all-args constructor with one argument per field, so its arity is fixed by the field count.
    // Collapsing the fields into a parameter object would break that generated call; this constructor
    // exists solely to add construction-time validation (L14) to the builder path.
    @SuppressWarnings("java:S107")
    ClientConfiguration(@NonNull String issuer, @NonNull String clientId, @Nullable String clientSecret,
            @NonNull ClientAuthMethod authMethod, List<String> scopes, @Nullable String redirectUri,
            boolean allowInsecureHttp, int connectTimeoutSeconds, int readTimeoutSeconds,
            @Nullable SSLContext sslContext) {
        this.issuer = requireNonBlank(issuer, "issuer");
        validateIssuerUrl(this.issuer);
        this.clientId = requireNonBlank(clientId, "clientId");
        this.clientSecret = validateClientSecret(clientSecret);
        this.authMethod = Objects.requireNonNull(authMethod, "authMethod must not be null");
        this.scopes = validateScopes(scopes);
        this.redirectUri = redirectUri;
        this.allowInsecureHttp = allowInsecureHttp;
        this.connectTimeoutSeconds = requirePositive(connectTimeoutSeconds, "connectTimeoutSeconds");
        this.readTimeoutSeconds = requirePositive(readTimeoutSeconds, "readTimeoutSeconds");
        // No validation: null means "use the cui-http / JVM default truststore", the unconfigured default.
        this.sslContext = sslContext;
    }

    /**
     * A client secret is optional (it is {@code null} for the key-based methods), but a
     * <em>provided</em> secret must carry an actual value: a blank/whitespace-only secret is a
     * misconfiguration that would otherwise be wired through the shared-secret auth strategies and
     * fail only later at the token endpoint. A blank secret is rejected; an absent ({@code null})
     * secret is preserved.
     */
    private static @Nullable String validateClientSecret(@Nullable String clientSecret) {
        if (clientSecret != null && clientSecret.isBlank()) {
            throw new IllegalArgumentException("clientSecret must not be blank when provided");
        }
        return clientSecret;
    }

    private static int requirePositive(int value, String field) {
        if (value <= 0) {
            throw new IllegalArgumentException(field + " must be positive, but was: " + value);
        }
        return value;
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    private static void validateIssuerUrl(String issuer) {
        final URI uri;
        try {
            uri = new URI(issuer);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("issuer must be a valid absolute URL, but was: " + issuer, e);
        }
        String scheme = uri.getScheme();
        if (!uri.isAbsolute() || uri.getHost() == null
                || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException(
                    "issuer must be an absolute http(s) URL with a host, but was: " + issuer);
        }
    }

    private static List<String> validateScopes(List<String> scopes) {
        Objects.requireNonNull(scopes, "scopes must not be null");
        for (String scope : scopes) {
            if (scope == null || scope.isBlank()) {
                throw new IllegalArgumentException("scopes must not contain null or blank entries");
            }
        }
        return List.copyOf(scopes);
    }
}
