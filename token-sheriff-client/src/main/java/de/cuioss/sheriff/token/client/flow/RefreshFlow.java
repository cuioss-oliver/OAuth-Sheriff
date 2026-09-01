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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.RotationResult.ScopeDelta;
import de.cuioss.sheriff.token.client.token.TokenResponse;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Drives the OAuth 2.0 {@code refresh_token} grant (RFC 6749 §6) with refresh-token rotation.
 * <p>
 * The flow builds the {@code grant_type=refresh_token} request, applies the configured
 * {@link ClientAuthentication} strategy (deliverable 3), exchanges it at the token endpoint through
 * {@link TokenEndpointClient}, and validates the returned access token through the
 * {@link TokenValidationBridge} ({@code CLIENT-15}). It returns only a validated token — a
 * successful HTTP exchange alone is never trusted.
 * <p>
 * When the authorization server issues a new refresh token (rotation, per the OAuth 2.0 Security
 * BCP), the {@link RotationResult} reports the rotated token and flags the rotation; the caller
 * feeds that transition into its {@link de.cuioss.sheriff.token.client.token.RefreshTokenFamily} so
 * a later replay of a superseded token is detected and the family revoked ({@code CLIENT-17}).
 * <p>
 * The flow also reconciles the scope the authorization server granted against the scope this client
 * requested, and reports the outcome on the {@link RotationResult}
 * ({@link RotationResult.ScopeDelta}). This is <strong>anomaly reporting, not compliance
 * enforcement</strong>: RFC 6749 §3.3 permits the server to grant a scope other than the one
 * requested provided it discloses the result, and the resource server remains the enforcement point
 * for an over-broad claim. A broadened grant is therefore accepted and {@code WARN}-logged by
 * default; it is refused with {@link ClientProtocolException} only when the deployment opts in via
 * {@code ClientConfiguration.strictScopeReconciliation}.
 * <p>
 * Both the validation refusal and the strict-posture scope refusal are raised <em>after</em> the token
 * endpoint has answered, and therefore after the authorization server has redeemed and possibly
 * rotated the presented refresh token — as is an unparseable success response, where rotation cannot
 * be determined at all. A caller holding a session cannot tell from those exceptions whether the token
 * it still has stored is alive or dead, so
 * {@link #refresh(ProviderMetadata, String, java.util.function.Consumer)} reports a
 * {@link RefreshRedemption} the moment the server has answered, before any check that could still
 * refuse. A failure raised before that point never reports one, which is what keeps a transient
 * network fault from being mistaken for a burned credential.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6 - Refreshing an Access Token</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics">OAuth 2.0 Security BCP</a>
 */
public class RefreshFlow {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshFlow.class);

    private static final String PARAM_GRANT_TYPE = "grant_type";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final String PARAM_REFRESH_TOKEN = "refresh_token";
    private static final String PARAM_SCOPE = "scope";

    /** The {@code scope} response parameter is a space-delimited list (RFC 6749 §3.3). */
    private static final String SCOPE_DELIMITER = " ";

    /** Splits a granted {@code scope} value on any run of whitespace. */
    private static final String SCOPE_SPLIT_PATTERN = "\\s+";

    /**
     * The observer installed by {@link #refresh(ProviderMetadata, String)}: a caller that did not ask
     * for the redemption signal is not interested in it.
     */
    private static final Consumer<RefreshRedemption> IGNORE_REDEMPTION = redemption -> {
        // The two-argument overload reports no redemption state.
    };

    private final ClientConfiguration configuration;
    private final TokenEndpointClient tokenEndpointClient;
    private final TokenValidationBridge validationBridge;
    private final ClientAuthentication clientAuthentication;
    @Nullable
    private final SenderConstraint senderConstraint;

    /**
     * Creates an unconstrained refresh flow (plain bearer token, no DPoP/mTLS).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     */
    public RefreshFlow(ClientConfiguration configuration,
            TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge validationBridge,
            ClientAuthentication clientAuthentication) {
        this(configuration, tokenEndpointClient, validationBridge, clientAuthentication, null);
    }

    /**
     * Creates a refresh flow that, when a sender-constraint is supplied, attaches a DPoP proof to the
     * refresh request so the rotated access token is issued bound to the proof key ({@code CLIENT-11}).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     * @param senderConstraint     the DPoP/mTLS sender-constraint to attach, or {@code null} for a
     *                             plain bearer refresh
     */
    public RefreshFlow(ClientConfiguration configuration,
            TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge validationBridge,
            ClientAuthentication clientAuthentication,
            @Nullable SenderConstraint senderConstraint) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.tokenEndpointClient = Objects.requireNonNull(tokenEndpointClient, "tokenEndpointClient must not be null");
        this.validationBridge = Objects.requireNonNull(validationBridge, "validationBridge must not be null");
        this.clientAuthentication = Objects.requireNonNull(clientAuthentication,
                "clientAuthentication must not be null");
        this.senderConstraint = senderConstraint;
    }

    /**
     * Exchanges a refresh token for a freshly validated access token, reporting any rotation and any
     * granted-scope delta.
     *
     * @param metadata     the resolved provider metadata carrying the token endpoint; must not be
     *                     {@code null}
     * @param refreshToken the refresh token to redeem; must not be {@code null} or blank
     * @return the rotation result carrying the validated access token, the refresh token to use
     *         next, the raw refreshed ID token (when the AS issued one) for the lifecycle
     *         consistency check (OIDC Core §12.2), and the granted scope with its reconciliation
     *         outcome
     * @throws de.cuioss.sheriff.token.commons.error.TransportException if the token request fails
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the returned
     *         token fails validation
     * @throws ClientProtocolException if the granted scope is broader than the requested scope and
     *         {@code ClientConfiguration.strictScopeReconciliation} is enabled; never in the default
     *         lenient posture
     */
    public RotationResult refresh(ProviderMetadata metadata, String refreshToken) {
        return refresh(metadata, refreshToken, IGNORE_REDEMPTION);
    }

    /**
     * Exchanges a refresh token as {@link #refresh(ProviderMetadata, String)} does, additionally
     * reporting to {@code redemptionObserver} what the authorization server did to the presented
     * refresh token — as soon as that is known, and independently of whether the exchange then
     * succeeds.
     * <p>
     * <strong>Why the extra signal exists.</strong> Several client-side checks run <em>after</em> the
     * authorization server has answered {@code 2xx} and therefore after it has consumed the presented
     * refresh token and, per its own rotation policy, possibly burned it: access-token validation, and
     * the strict scope-reconciliation refusal. Each of those throws before a {@link RotationResult}
     * exists, so a caller holding a session cannot tell from the exception alone whether the token it
     * still has stored is alive or dead. This overload closes that gap without changing the exception
     * contract above: the observer has already been called by the time any such refusal is thrown.
     * <p>
     * <strong>The observer is called at most once, and only after redemption.</strong> A failure
     * raised before the server processed the request — a connection failure, a DNS failure, an
     * SSRF-blocked target, or a non-success HTTP status — never reaches it. An observer that was not
     * called therefore means the presented refresh token is untouched and still valid, which is
     * exactly what stops a transient network fault from destroying a working session. The one case
     * where redemption happened but rotation is unrecoverable — a {@code 2xx} whose body cannot be
     * parsed, so no {@link de.cuioss.sheriff.token.client.token.TokenResponse} is ever constructed —
     * is reported as {@link RefreshRedemption#rotationUnknown()} and fails closed.
     *
     * @param metadata           the resolved provider metadata carrying the token endpoint; must not
     *                           be {@code null}
     * @param refreshToken       the refresh token to redeem; must not be {@code null} or blank
     * @param redemptionObserver notified with the redemption state once the authorization server has
     *                           answered successfully, before any client-side check that could still
     *                           refuse the exchange; must not be {@code null}
     * @return the rotation result, as {@link #refresh(ProviderMetadata, String)}
     * @throws de.cuioss.sheriff.token.commons.error.TransportException if the token request fails
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the returned
     *         token fails validation
     * @throws ClientProtocolException if the granted scope is broader than the requested scope and
     *         {@code ClientConfiguration.strictScopeReconciliation} is enabled
     */
    public RotationResult refresh(ProviderMetadata metadata, String refreshToken,
            Consumer<RefreshRedemption> redemptionObserver) {
        Objects.requireNonNull(redemptionObserver, "redemptionObserver must not be null");
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        if (refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken must not be blank");
        }
        String tokenEndpoint = metadata.getTokenEndpoint()
                .orElseThrow(() -> new IllegalStateException("provider metadata is missing the token endpoint"));

        Map<String, String> form = new HashMap<>(Map.of(
                PARAM_GRANT_TYPE, GRANT_REFRESH_TOKEN,
                PARAM_REFRESH_TOKEN, refreshToken));
        if (!configuration.getScopes().isEmpty()) {
            form.put(PARAM_SCOPE, String.join(SCOPE_DELIMITER, configuration.getScopes()));
        }

        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        TokenResponse tokenResponse;
        try {
            tokenResponse = tokenEndpointClient.requestToken(tokenEndpoint, form, headers, senderConstraint);
        } catch (RedeemedResponseException unusableResponse) {
            // The server answered 2xx — it redeemed the presented token — but the body is unusable, so
            // its rotation decision is not recoverable here or anywhere else on the client. Report it
            // as unknown so the caller fails closed on a presumed rotation rather than keeping a token
            // that may already be dead. A pre-redemption failure carries no RedeemedResponseException
            // and is deliberately left to propagate unreported, leaving the presented token in use.
            redemptionObserver.accept(RefreshRedemption.rotationUnknown());
            throw unusableResponse;
        }

        // Rotation is resolved and reported BEFORE the client-side checks below, because each of them
        // can refuse the exchange after the server has already burned the presented token.
        String rotatedRefreshToken = resolveRefreshToken(refreshToken, tokenResponse.refreshToken);
        boolean rotated = !rotatedRefreshToken.equals(refreshToken);
        redemptionObserver.accept(rotated
                ? RefreshRedemption.rotated(rotatedRefreshToken)
                : RefreshRedemption.notRotated());

        AccessTokenContent accessToken = validationBridge.validateAccessToken(tokenResponse.accessToken);
        LOGGER.debug("Refreshed access token for client '%s' (rotated=%s)", configuration.getClientId(), rotated);

        String grantedScope = tokenResponse.getScope().orElse(null);
        ScopeDelta scopeDelta = classifyScopeDelta(grantedScope);
        reportScopeDelta(scopeDelta, grantedScope);

        return new RotationResult(accessToken, rotatedRefreshToken, tokenResponse.idToken,
                tokenResponse.expiresIn, rotated, grantedScope, scopeDelta);
    }

    /**
     * Classifies the scope the authorization server granted against the scope this client requested.
     * <p>
     * A pure query — it neither logs nor throws; {@link #reportScopeDelta(ScopeDelta, String)} owns
     * those effects. Reconciliation is skipped (yielding {@link ScopeDelta#UNDECLARED}) when this
     * client requested no scope, since there is then no baseline to compare against, and when the AS
     * omitted the {@code scope} parameter, which RFC 6749 §5.1 defines as identical to the requested
     * scope.
     * <p>
     * A granted set that both adds an unrequested scope and drops a requested one is classified
     * {@link ScopeDelta#BROADENED}: the unrequested member is the signal that matters, and folding the
     * mixed case into the broader classification keeps the opt-in strict posture from silently
     * accepting a grant it was enabled to refuse.
     *
     * @param grantedScope the raw granted {@code scope} value, or {@code null} when the AS omitted it
     * @return the reconciliation outcome; never {@code null}
     */
    private ScopeDelta classifyScopeDelta(@Nullable String grantedScope) {
        List<String> requestedScopes = configuration.getScopes();
        if (requestedScopes.isEmpty() || grantedScope == null || grantedScope.isBlank()) {
            return ScopeDelta.UNDECLARED;
        }
        Set<String> granted = new HashSet<>(Arrays.asList(grantedScope.trim().split(SCOPE_SPLIT_PATTERN)));
        Set<String> requested = new HashSet<>(requestedScopes);
        if (granted.equals(requested)) {
            return ScopeDelta.EQUAL;
        }
        if (requested.containsAll(granted)) {
            return ScopeDelta.NARROWED;
        }
        return ScopeDelta.BROADENED;
    }

    /**
     * Applies the configured disposition for a reconciliation outcome.
     * <p>
     * A broadened grant is refused with {@link ClientProtocolException} only under the opt-in strict
     * posture ({@code ClientConfiguration.strictScopeReconciliation}); by default it is accepted and
     * reported at {@code WARN} so the delta is observable rather than invisible. A narrowed grant is
     * accepted and reported in both postures. {@link ScopeDelta#EQUAL} and
     * {@link ScopeDelta#UNDECLARED} are accepted silently.
     * <p>
     * The granted value crossed a trust boundary, so it is sanitized before interpolation into the log
     * template and the exception message (CWE-117 log forging).
     *
     * @param scopeDelta   the reconciliation outcome
     * @param grantedScope the raw granted {@code scope} value, or {@code null} when the AS omitted it
     * @throws ClientProtocolException when the grant is broadened and strict reconciliation is enabled
     */
    private void reportScopeDelta(ScopeDelta scopeDelta, @Nullable String grantedScope) {
        if (scopeDelta == ScopeDelta.EQUAL || scopeDelta == ScopeDelta.UNDECLARED) {
            return;
        }
        String safeGranted = LogSanitizer.sanitize(grantedScope);
        String requested = String.join(SCOPE_DELIMITER, configuration.getScopes());
        if (scopeDelta == ScopeDelta.NARROWED) {
            LOGGER.warn(ClientLogMessages.WARN.SCOPE_NARROWED, safeGranted, requested);
            return;
        }
        if (configuration.isStrictScopeReconciliation()) {
            throw new ClientProtocolException(
                    "Authorization server granted a broader scope than requested on refresh; granted '"
                            + safeGranted + "', requested '" + requested
                            + "'. Refused because strictScopeReconciliation is enabled.");
        }
        LOGGER.warn(ClientLogMessages.WARN.SCOPE_BROADENED, safeGranted, requested);
    }

    /**
     * Resolves the refresh token to use for the next refresh: the rotated token the AS returned, or
     * the presented token when the AS chose not to rotate (RFC 6749 §6 permits omitting it).
     */
    private static String resolveRefreshToken(String presented, String issued) {
        if (issued != null && !issued.isBlank()) {
            return issued;
        }
        return presented;
    }
}
