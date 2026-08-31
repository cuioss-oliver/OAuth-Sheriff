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

import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.tools.logging.CuiLogger;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Tracks a single refresh-token rotation family and enforces revoke-on-reuse ({@code CLIENT-17}).
 * <p>
 * Each redemption of a refresh token rotates it to a new value (OAuth 2.0 Security BCP): the
 * superseded token is retired and only the current token may be redeemed next. Presenting a
 * superseded token again is the signature of a stolen-token replay — the family is then
 * <em>revoked</em> and every further redemption fails closed, so an attacker who captured an old
 * refresh token cannot ride it into a valid session.
 * <p>
 * The family is thread-safe: concurrent redemptions of the same current token are serialized so
 * that exactly one wins the rotation and every loser is treated as a reuse of the now-superseded
 * token, revoking the family.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics">OAuth 2.0 Security BCP §4.13</a>
 */
public class RefreshTokenFamily {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshTokenFamily.class);

    private final ReentrantLock lock = new ReentrantLock();

    private String currentToken;
    private boolean revoked;

    /**
     * @param initialRefreshToken the first refresh token issued for this family; must not be
     *                            {@code null} or blank
     */
    public RefreshTokenFamily(String initialRefreshToken) {
        this.currentToken = requireNonBlank(initialRefreshToken);
    }

    /**
     * Atomically redeems the presented refresh token and advances the family to its rotated
     * successor.
     * <p>
     * The presented token must be the current active token. Presenting a superseded token — or any
     * token that is not current — is treated as reuse: the family is revoked and a
     * {@link ClientProtocolException} is thrown. Once revoked, every subsequent call fails closed.
     *
     * @param presentedToken the refresh token being redeemed; must not be {@code null} or blank
     * @param rotatedToken   the successor refresh token the AS issued; must not be {@code null} or
     *                       blank, and must differ from {@code presentedToken}
     * @throws ClientProtocolException  if the family is already revoked, or reuse is detected (which
     *                                  also revokes the family)
     * @throws IllegalArgumentException if {@code rotatedToken} equals {@code presentedToken}
     */
    public void rotate(String presentedToken, String rotatedToken) {
        requireNonBlank(presentedToken);
        requireNonBlank(rotatedToken);
        if (rotatedToken.equals(presentedToken)) {
            throw new IllegalArgumentException("rotatedToken must differ from the presented token");
        }
        lock.lock();
        try {
            assertRedeemable(presentedToken);
            currentToken = rotatedToken;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Reverts a tentative {@link #rotate} when the write it was performed for is subsequently
     * refused, so the family stays in agreement with a store that was never actually updated.
     * <p>
     * {@link #rotate} advances {@link #currentToken} the moment it confirms {@code presentedToken}
     * was current; it has no visibility into what the caller does with that outcome next. When the
     * caller's own downstream write is then refused — for example a stored session's identity or
     * sender-constraint binding check rejects the refresh — the caller's persisted state (the token
     * store) keeps the pre-refresh token, but this family has already moved past it. Left uncorrected,
     * the next legitimate redemption presents that still-valid, still-stored token, which the family
     * now sees as superseded and misclassifies as reuse — self-inflicting a revoke-and-clear of a
     * session that was never actually compromised.
     * <p>
     * Only takes effect when {@link #currentToken} is still exactly {@code rotatedToken} (the value
     * this family's own {@link #rotate} just installed) and the family has not been revoked: a no-op
     * otherwise, so a family already advanced again by a later redemption, or revoked by a genuine
     * reuse detection in the meantime, is left untouched rather than clobbered by a stale revert.
     *
     * @param presentedToken the token to restore as current; must not be {@code null} or blank
     * @param rotatedToken   the tentatively-installed successor to revert, iff still current; must not
     *                       be {@code null} or blank
     */
    public void revertRotation(String presentedToken, String rotatedToken) {
        requireNonBlank(presentedToken);
        requireNonBlank(rotatedToken);
        lock.lock();
        try {
            if (!revoked && rotatedToken.equals(currentToken)) {
                currentToken = presentedToken;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * @return whether this family has been revoked (by reuse detection)
     */
    public boolean isRevoked() {
        lock.lock();
        try {
            return revoked;
        } finally {
            lock.unlock();
        }
    }

    /**
     * @return the current active refresh token
     * @throws ClientProtocolException if the family has been revoked
     */
    public String currentToken() {
        lock.lock();
        try {
            if (revoked) {
                throw new ClientProtocolException("refresh token family is revoked");
            }
            return currentToken;
        } finally {
            lock.unlock();
        }
    }

    private void assertRedeemable(String presentedToken) {
        if (revoked) {
            throw new ClientProtocolException("refresh token family is revoked");
        }
        if (!currentToken.equals(presentedToken)) {
            revoked = true;
            LOGGER.warn(ClientLogMessages.WARN.REFRESH_TOKEN_REUSE);
            throw new ClientProtocolException(
                    "refresh token reuse detected; the refresh token family has been revoked");
        }
    }

    private static String requireNonBlank(String value) {
        Objects.requireNonNull(value, "refresh token must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("refresh token must not be blank");
        }
        return value;
    }
}
