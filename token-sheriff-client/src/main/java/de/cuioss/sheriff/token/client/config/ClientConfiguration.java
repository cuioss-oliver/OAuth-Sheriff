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
     * Default byte ceiling for the OIDC discovery document, when the caller does not override it:
     * 64&nbsp;KiB. Sized for what a discovery document actually is — a stock Keycloak realm already
     * publishes upwards of 8&nbsp;KiB, and a document that enumerates a large
     * {@code claims_supported} / {@code scopes_supported} set grows well past that — while still
     * bounding the read so an unbounded response cannot be buffered.
     */
    public static final int DEFAULT_DISCOVERY_DOCUMENT_MAX_SIZE = 64 * 1024;

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
     * Whether TLS hostname verification is performed for every outbound discovery and back-channel
     * call. Defaults to {@code true}, so the certificate presented must match the host contacted.
     * <p>
     * Setting this to {@code false} relaxes <strong>hostname matching only</strong>: certificate chain
     * trust, expiry, and algorithm constraints all remain fully enforced, so an untrusted or expired
     * certificate is still rejected.
     * <p>
     * This field is mutually exclusive with {@link #sslContext}. The relaxation applies only to the
     * default-trust-store context the underlying HTTP handler derives, so a caller-supplied context
     * leaves nothing to relax; the constructor rejects the combination with an
     * {@link IllegalArgumentException}. When verification is disabled, trust material must therefore be
     * supplied through the JVM default trust store rather than per-client.
     * <p>
     * It is independent of {@link #allowInsecureHttp}, which governs the URL <em>scheme</em> rather than
     * certificate matching; the two axes may be set in any combination that does not also set
     * {@link #sslContext}.
     * <p>
     * <strong>Never set this to {@code false} in production.</strong> Disabling hostname verification
     * removes the guarantee that the certificate presented belongs to the host actually contacted, which
     * re-opens the man-in-the-middle vector that chain validation alone does not close. It exists for
     * local development and test topologies serving SAN-mismatched certificates.
     */
    @Builder.Default
    boolean verifyHostname = true;

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
     * The maximum size, in bytes, of the authorization server's
     * {@code .well-known/openid-configuration} response, enforced during the read. Defaults to
     * {@value #DEFAULT_DISCOVERY_DOCUMENT_MAX_SIZE} bytes.
     * <p>
     * A discovery document is an unrelated artifact to a JWT payload and has its own size profile, so
     * it carries its own ceiling rather than borrowing the JWT payload ceiling
     * ({@code ParserConfig.getMaxPayloadSize()}, 8&nbsp;KiB) — a bound an ordinary Keycloak realm
     * already exceeds, which failed discovery outright. Exposing it here also gives an embedder facing
     * an unusually large document a deployment-side route that does not require a release.
     * <p>
     * Must be positive. Raising it widens how much of an authorization-server response is buffered;
     * keep it as tight as the deployment's actual documents allow.
     */
    @Builder.Default
    int discoveryDocumentMaxSize = DEFAULT_DISCOVERY_DOCUMENT_MAX_SIZE;

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
     * Whether a refresh whose granted scope is <em>broader</em> than the requested scope is refused.
     * Defaults to {@code false}.
     * <p>
     * <strong>Default (lenient, {@code false}):</strong> a broadened grant is accepted, logged at
     * {@code WARN}, and surfaced on {@code RotationResult} as {@code scopeDelta=BROADENED} with the
     * raw {@code grantedScope}, so the calling application can act on the delta. This is the correct
     * default: RFC 6749 §3.3 permits an authorization server to grant a scope other than the one
     * requested provided it discloses the result, several major authorization servers canonicalise or
     * expand scope sets as a matter of course, and the resource server remains the enforcement point
     * for a claim that was never actually granted. Refusing by default would convert a benign server
     * quirk into a total authentication outage with no attacker in the loop.
     * <p>
     * <strong>Strict ({@code true}):</strong> a broadened grant raises
     * {@code ClientProtocolException} and no result is produced. Enable this <em>only</em> against an
     * authorization server known not to canonicalise or expand scope sets — the outage risk above is
     * real and falls entirely on the deployment that opts in. Its only profile precedent is FAPI 1.0
     * Part 1 §5.2.3(10), an authorization-code-response rule that FAPI 2.0 dropped.
     * <p>
     * The flag changes nothing else: a <em>narrowed</em> grant is accepted and {@code WARN}-logged in
     * both postures, and an equal or absent granted scope is accepted silently in both. Reconciliation
     * is skipped entirely when {@link #getScopes()} is empty, since no scope was requested and there is
     * no baseline to compare against.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3 - Access Token Scope</a>
     */
    @Builder.Default
    boolean strictScopeReconciliation = false;

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
            boolean allowInsecureHttp, boolean verifyHostname, int connectTimeoutSeconds, int readTimeoutSeconds,
            int discoveryDocumentMaxSize, @Nullable SSLContext sslContext,
            boolean strictScopeReconciliation) {
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
        this.discoveryDocumentMaxSize = requirePositive(discoveryDocumentMaxSize, "discoveryDocumentMaxSize");
        // Fail fast here rather than at the first token exchange. BackChannelHttp's validatedHandler
        // applies a caller-supplied sslContext inside an exception handler that rewraps the failure
        // as a TransportException, so without this guard an incompatible configuration would build
        // cleanly and only surface later as a transport failure rather than the configuration error
        // it actually is.
        if (sslContext != null && !verifyHostname) {
            throw new IllegalArgumentException(
                    "verifyHostname(false) cannot be combined with sslContext(...). The hostname relaxation applies "
                            + "only to the default-trust-store context the HTTP handler derives, so a caller-supplied "
                            + "context leaves nothing to relax. Either drop sslContext(...) and supply trust through "
                            + "the JVM default trust store, or keep verifyHostname(true).");
        }
        this.verifyHostname = verifyHostname;
        // No validation: null means "use the cui-http / JVM default truststore", the unconfigured default.
        this.sslContext = sslContext;
        // No validation: a boolean has no invalid value.
        this.strictScopeReconciliation = strictScopeReconciliation;
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

    /**
     * Validates that each configured entry is exactly one OAuth scope-token.
     * <p>
     * RFC 6749 §3.3 defines {@code scope} as a space-delimited list of individual scope-tokens, so a
     * request joins the configured entries with a single space. An entry carrying embedded whitespace
     * would go out as two or more scope-tokens while still counting as a single configured member,
     * which leaves the requested set and the wire representation disagreeing: granted-scope
     * reconciliation would then compare {@code {"read write"}} against the granted {@code {read,
     * write}} and misreport an exactly-as-requested grant as broadened. Rejecting the entry here keeps
     * the two in agreement, so no malformed scope list can reach the reconciliation logic at all.
     *
     * @param scopes the configured scopes; must not be {@code null} and must hold one scope-token per
     *               entry
     * @return an immutable copy of the validated scopes
     * @throws IllegalArgumentException if an entry is blank or is not a single scope-token
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</a>
     */
    private static List<String> validateScopes(List<String> scopes) {
        Objects.requireNonNull(scopes, "scopes must not be null");
        for (String scope : scopes) {
            if (scope == null || scope.isBlank()) {
                throw new IllegalArgumentException("scopes must not contain null or blank entries");
            }
            if (scope.codePoints().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException(
                        "scopes must hold one scope-token per entry (RFC 6749 §3.3), but was: " + scope);
            }
        }
        return List.copyOf(scopes);
    }
}
