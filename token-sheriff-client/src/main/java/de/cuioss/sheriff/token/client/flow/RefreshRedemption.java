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

import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * What the authorization server did to the presented refresh token, reported the moment it is known
 * and independently of whether the refresh subsequently succeeds.
 * <p>
 * A {@link de.cuioss.sheriff.token.client.token.RotationResult} is only ever constructed on the
 * success path, so a caller that must fail
 * closed after a <em>post-redemption</em> refusal has no result to inspect. This value is the
 * separate signal: {@link RefreshFlow} resolves it as soon as the token endpoint has answered and
 * carries it on every refusal raised thereafter ({@link RedeemedRefreshFailure}), which
 * {@link RefreshFlow#redemptionOf(Throwable)} reads back. Its absence is therefore just as meaningful
 * as its presence: a failure carrying none means the request failed <em>before</em> the authorization
 * server processed it (connection failure, DNS failure, non-success HTTP status), so the presented
 * refresh token is still valid and the session must not be quarantined.
 * <p>
 * Three states are distinguished, and the third is not a variant of the first two:
 * <ul>
 *   <li>{@link #rotated(String)} — the server issued a successor; the presented token is burned.</li>
 *   <li>{@link #notRotated()} — the server reused the presented token (RFC 6749 §6 permits omitting
 *       a new one); it is still valid.</li>
 *   <li>{@link #rotationUnknown()} — the server answered {@code 2xx} but the response could not be
 *       parsed, so no successor is known <em>and rotation is not computable even in principle</em>.
 *       This is the fail-closed state: the presented token is treated as burned, but there is no
 *       successor to revoke.</li>
 * </ul>
 *
 * @param rotatedRefreshToken the successor the authorization server issued, or {@code null} when it
 *                            did not rotate or when rotation is unknown. Never a fabricated value:
 *                            {@code null} on the unknown state means "no token to revoke", not "no
 *                            rotation happened"
 * @param rotationKnown       whether the response was usable enough to determine rotation at all;
 *                            {@code false} only for {@link #rotationUnknown()}
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6 - Refreshing an Access Token</a>
 */
public record RefreshRedemption(@Nullable String rotatedRefreshToken, boolean rotationKnown) {

    /**
     * @param rotatedRefreshToken the successor the authorization server issued; must not be
     *                            {@code null} or blank
     * @return the redemption state for a rotating authorization server
     */
    public static RefreshRedemption rotated(String rotatedRefreshToken) {
        Objects.requireNonNull(rotatedRefreshToken, "rotatedRefreshToken must not be null");
        if (rotatedRefreshToken.isBlank()) {
            throw new IllegalArgumentException("rotatedRefreshToken must not be blank");
        }
        return new RefreshRedemption(rotatedRefreshToken, true);
    }

    /**
     * @return the redemption state for a server that redeemed the presented token without rotating it
     */
    public static RefreshRedemption notRotated() {
        return new RefreshRedemption(null, true);
    }

    /**
     * @return the redemption state for a {@code 2xx} response that could not be parsed, where the
     *         server's rotation decision is unrecoverable and the presented token must be presumed
     *         burned
     */
    public static RefreshRedemption rotationUnknown() {
        return new RefreshRedemption(null, false);
    }

    /**
     * Whether the presented refresh token must be presumed dead at the authorization server, and the
     * session therefore quarantined rather than left holding it.
     * <p>
     * True both when a successor is known ({@link #rotated(String)}) and when rotation could not be
     * determined ({@link #rotationUnknown()}) — the unknown case fails closed. False only for
     * {@link #notRotated()}, where the presented token demonstrably survived the exchange.
     *
     * @return whether the presented token must be treated as burned
     */
    public boolean presentedTokenBurned() {
        return !rotationKnown || rotatedRefreshToken != null;
    }

    /**
     * Renders the state without exposing live token material: the rotated refresh token is a usable
     * credential, so a stray {@code toString()} in a log statement, exception message or debugger dump
     * must not leak it (H8, matching
     * {@link de.cuioss.sheriff.token.client.token.RotationResult#toString()}). Only its presence is
     * shown.
     *
     * @return a redacted string representation carrying no live token material
     */
    @Override
    public String toString() {
        return "RefreshRedemption[rotatedRefreshToken="
                + (rotatedRefreshToken == null ? "null" : "<redacted>")
                + ", rotationKnown=" + rotationKnown + "]";
    }
}
