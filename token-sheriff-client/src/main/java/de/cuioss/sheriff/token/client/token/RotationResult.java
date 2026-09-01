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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * The outcome of an OAuth 2.0 {@code refresh_token} exchange
 * ({@link de.cuioss.sheriff.token.client.flow.RefreshFlow}).
 * <p>
 * Carries the freshly validated access token, the refresh token to present on the next refresh,
 * the refreshed ID token (when the AS issued one), and whether the authorization server rotated the
 * refresh token. When {@link #rotated()} is {@code true} the {@link #refreshToken()} is the
 * AS-issued successor and the presented token has been superseded; when {@code false} the AS chose
 * not to rotate (RFC 6749 §6 permits omitting a new refresh token) and {@link #refreshToken()} is
 * the still-valid presented token.
 * <p>
 * The {@link #idToken()} is the raw ID token the AS returned on the refresh, or {@code null} when it
 * omitted one (OIDC Core §12.2 makes the ID token optional on refresh). The lifecycle wiring
 * verifies its {@code iss}/{@code sub} consistency against the validated access token before it is
 * carried forward, rather than silently preserving the pre-refresh ID token.
 * <p>
 * {@link #grantedScope()} and {@link #scopeDelta()} report the outcome of reconciling the scope the
 * authorization server actually granted against the scope this client requested. This is
 * <strong>anomaly reporting, not compliance enforcement</strong>: RFC 6749 §3.3 affirmatively permits
 * an authorization server to grant a scope other than the one requested, obliging it only to disclose
 * the result through the {@code scope} response parameter, and the resource server — not this client —
 * remains the enforcement point for an over-broad claim. A {@link ScopeDelta#BROADENED} outcome is
 * therefore surfaced for the calling application to act on, never presented as a protocol violation.
 *
 * @param accessToken               the validated access token content; never {@code null}
 * @param refreshToken              the refresh token to use on the next refresh; never {@code null}
 *                                  or blank
 * @param idToken                   the raw refreshed ID token, or {@code null} when the AS omitted it
 * @param accessTokenExpiresInSeconds the access token lifetime in seconds ({@code 0} when the AS
 *                                  omits {@code expires_in})
 * @param rotated                   whether the refresh token was rotated by this exchange
 * @param grantedScope              the raw {@code scope} value the authorization server returned, or
 *                                  {@code null} when it omitted the parameter. {@code null} does
 *                                  <strong>not</strong> mean "no scope was granted": RFC 6749 §5.1
 *                                  defines an omitted {@code scope} as identical to the requested
 *                                  scope, so an absent value means "as requested", and the
 *                                  accompanying {@link #scopeDelta()} is {@link ScopeDelta#UNDECLARED}
 * @param scopeDelta                how the granted scope relates to the requested scope; never
 *                                  {@code null}
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OIDC Core §12.2</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3 - Access Token Scope</a>
 */
public record RotationResult(AccessTokenContent accessToken, String refreshToken,
@Nullable
String idToken, long accessTokenExpiresInSeconds, boolean rotated,
@Nullable
String grantedScope, ScopeDelta scopeDelta) {

    /**
     * How the scope the authorization server granted relates to the scope this client requested.
     * <p>
     * The classification is a <em>report</em>, not a verdict: only {@link #BROADENED} is ever
     * actionable as a refusal, and only when the client has opted in via
     * {@code ClientConfiguration.strictScopeReconciliation}. In the default lenient posture every
     * outcome is accepted.
     * <p>
     * <strong>Mirrored in the specification.</strong> These four constants and their per-mode
     * disposition are reproduced as the "full mode &times; outcome contract" table in
     * {@code doc/client/specification/token-handling.adoc}. The table is hand-authored, not generated:
     * adding, removing or renaming a constant here — or changing what a posture does with one —
     * requires updating that table in the same change, or the specification goes silently stale.
     *
     * @since 1.0
     */
    public enum ScopeDelta {

        /** The granted scope set is exactly the requested scope set. Accepted silently. */
        EQUAL,

        /**
         * The granted scope set is a strict subset of the requested set — the authorization server
         * withheld at least one requested scope. Accepted and {@code WARN}-logged in both postures.
         */
        NARROWED,

        /**
         * The granted scope set contains at least one scope this client did not request. Accepted,
         * {@code WARN}-logged and surfaced in the default lenient posture; refused with a
         * {@code ClientProtocolException} only under the opt-in strict posture.
         */
        BROADENED,

        /**
         * No reconciliation was performed: either this client requested no scope at all (so there is
         * no baseline to compare against), or the authorization server omitted the {@code scope}
         * response parameter — which RFC 6749 §5.1 defines as identical to the requested scope, and
         * which is therefore not a broadening signal. Accepted silently.
         */
        UNDECLARED
    }

    /**
     * @param accessToken               the validated access token content; must not be {@code null}
     * @param refreshToken              the refresh token to use next; must not be {@code null} or blank
     * @param idToken                   the raw refreshed ID token, or {@code null} when the AS omitted it
     * @param accessTokenExpiresInSeconds the access token lifetime in seconds
     * @param rotated                   whether the refresh token was rotated
     * @param grantedScope              the raw granted {@code scope} value, or {@code null} when the AS
     *                                  omitted it
     * @param scopeDelta                the reconciliation outcome; must not be {@code null}
     */
    public RotationResult {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        if (refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken must not be blank");
        }
        Objects.requireNonNull(scopeDelta, "scopeDelta must not be null");
    }

    /**
     * Renders the result without exposing live token material: the validated access token, the
     * refresh token, and the refreshed ID token are redacted so a stray {@code toString()} — a log
     * statement, an exception message, or a debugger dump — never leaks a usable credential (H8). Only
     * credential presence and the non-secret fields are shown. {@code grantedScope} and
     * {@code scopeDelta} are authorization metadata rather than credentials, so both are rendered in
     * full — they are what makes a grant delta diagnosable from a log line.
     *
     * @return a redacted string representation carrying no live token material
     */
    @Override
    public String toString() {
        return "RotationResult[accessToken=<redacted>, refreshToken=<redacted>, idToken="
                + (idToken == null ? "null" : "<redacted>")
                + ", accessTokenExpiresInSeconds=" + accessTokenExpiresInSeconds
                + ", rotated=" + rotated
                + ", grantedScope=" + grantedScope
                + ", scopeDelta=" + scopeDelta + "]";
    }
}
