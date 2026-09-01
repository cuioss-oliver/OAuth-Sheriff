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

import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.util.Objects;

/**
 * The access token a refresh returned failed client-side validation, raised after the authorization
 * server had already redeemed the presented refresh token.
 * <p>
 * It extends {@link TokenValidationException} and carries the original refusal's
 * {@link TokenValidationException#getEventType() event type}, message and cause, so every existing
 * {@code catch (TokenValidationException)} and every documented
 * {@code @throws TokenValidationException} contract keeps holding unchanged — including the
 * {@code EventCategory}-driven RFC 9457 mapping at an HTTP edge. Only a caller that needs the
 * pre-/post-redemption distinction reads the additional {@link #redemption()}.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class RedeemedValidationRefusalException extends TokenValidationException
        implements RedeemedRefreshFailure {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Deliberately {@code transient}: {@link RefreshRedemption#rotatedRefreshToken()} is live
     * credential material, and an exception is serializable, so leaving it in the serialized form
     * would carry a usable refresh token onto whatever channel serialized the throwable (session
     * replication, remoting, a serializing log appender). {@link #redemption()} degrades to the
     * fail-closed state instead, which quarantines without naming a token to revoke.
     */
    @Nullable
    private final transient RefreshRedemption redemption;

    /**
     * @param refusal    the validation refusal to carry forward; must not be {@code null}
     * @param redemption what the authorization server did to the presented refresh token before the
     *                   refusal was raised; must not be {@code null}
     */
    public RedeemedValidationRefusalException(TokenValidationException refusal, RefreshRedemption redemption) {
        super(Objects.requireNonNull(refusal, "refusal must not be null").getEventType(),
                refusal.getMessage(), refusal);
        this.redemption = Objects.requireNonNull(redemption, "redemption must not be null");
    }

    /**
     * {@inheritDoc}
     * <p>
     * On a deserialized instance the carried state is gone by construction (see the field), so this
     * reports {@link RefreshRedemption#rotationUnknown()}: still redeemed, still fail-closed, but with
     * no successor to revoke. It never reports {@link RefreshRedemption#notRotated()} on that path,
     * because that is the one state which would leave the session holding the presented token.
     */
    @Override
    public RefreshRedemption redemption() {
        return redemption == null ? RefreshRedemption.rotationUnknown() : redemption;
    }
}
