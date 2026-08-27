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
 *
 * @param accessToken               the validated access token content; never {@code null}
 * @param refreshToken              the refresh token to use on the next refresh; never {@code null}
 *                                  or blank
 * @param idToken                   the raw refreshed ID token, or {@code null} when the AS omitted it
 * @param accessTokenExpiresInSeconds the access token lifetime in seconds ({@code 0} when the AS
 *                                  omits {@code expires_in})
 * @param rotated                   whether the refresh token was rotated by this exchange
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OIDC Core §12.2</a>
 */
public record RotationResult(AccessTokenContent accessToken, String refreshToken,
@Nullable
String idToken, long accessTokenExpiresInSeconds, boolean rotated) {

    /**
     * @param accessToken               the validated access token content; must not be {@code null}
     * @param refreshToken              the refresh token to use next; must not be {@code null} or blank
     * @param idToken                   the raw refreshed ID token, or {@code null} when the AS omitted it
     * @param accessTokenExpiresInSeconds the access token lifetime in seconds
     * @param rotated                   whether the refresh token was rotated
     */
    public RotationResult {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        if (refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken must not be blank");
        }
    }

    /**
     * Renders the result without exposing live token material: the validated access token, the
     * refresh token, and the refreshed ID token are redacted so a stray {@code toString()} — a log
     * statement, an exception message, or a debugger dump — never leaks a usable credential (H8). Only
     * credential presence and the non-secret fields are shown.
     *
     * @return a redacted string representation carrying no live token material
     */
    @Override
    public String toString() {
        return "RotationResult[accessToken=<redacted>, refreshToken=<redacted>, idToken="
                + (idToken == null ? "null" : "<redacted>")
                + ", accessTokenExpiresInSeconds=" + accessTokenExpiresInSeconds
                + ", rotated=" + rotated + "]";
    }
}
