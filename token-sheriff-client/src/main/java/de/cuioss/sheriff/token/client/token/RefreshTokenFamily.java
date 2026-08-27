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
