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

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.util.Objects;

/**
 * The authorization server granted a broader scope than requested and the opt-in strict
 * reconciliation posture refused the grant, after the server had already redeemed the presented
 * refresh token.
 * <p>
 * It extends {@link ClientProtocolException}, so every existing {@code catch (ClientProtocolException)}
 * and every documented {@code @throws ClientProtocolException} contract keeps holding unchanged — the
 * refusal still maps to the same RFC 9457 status at an HTTP edge. Only a caller that needs the
 * pre-/post-redemption distinction reads the additional {@link #redemption()}.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class RedeemedScopeRefusalException extends ClientProtocolException implements RedeemedRefreshFailure {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Deliberately {@code transient}, for the reason given on
     * {@link RedeemedValidationRefusalException}: the carried successor is live credential material
     * and must not ride an exception across a serialization boundary.
     */
    @Nullable
    private final transient RefreshRedemption redemption;

    /**
     * @param message    the caller-safe detail message; must not be {@code null}
     * @param redemption what the authorization server did to the presented refresh token before the
     *                   refusal was raised; must not be {@code null}
     */
    public RedeemedScopeRefusalException(String message, RefreshRedemption redemption) {
        super(message);
        this.redemption = Objects.requireNonNull(redemption, "redemption must not be null");
    }

    /**
     * {@inheritDoc}
     * <p>
     * Degrades to {@link RefreshRedemption#rotationUnknown()} on a deserialized instance, matching
     * {@link RedeemedValidationRefusalException#redemption()}.
     */
    @Override
    public RefreshRedemption redemption() {
        return redemption == null ? RefreshRedemption.rotationUnknown() : redemption;
    }
}
