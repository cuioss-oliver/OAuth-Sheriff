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

import de.cuioss.sheriff.token.commons.error.TransportException;

import java.io.Serial;

/**
 * Signals that the authorization server answered the token request with a success status — so it
 * accepted the request, processed the grant, and <em>redeemed</em> whatever credential was presented
 * — but the response body could not be turned into a usable {@code TokenResponse}.
 * <p>
 * The distinction this type carries is security-relevant and cannot be recovered by the caller: a
 * failure raised <em>before</em> the {@code 2xx} — a connection failure, a DNS failure, an
 * SSRF-blocked target, or a non-success HTTP status — leaves the presented credential untouched at
 * the authorization server, while a failure raised <em>after</em> it means the server has already
 * consumed the grant. On the {@code refresh_token} grant specifically the presented refresh token may
 * by then have been rotated and burned server-side, and because no {@code TokenResponse} is ever
 * constructed on this path, whether it was rotated is not computable from the client at all. Callers
 * that must fail closed therefore treat this exception as <strong>presumed redeemed</strong> — see
 * {@link RefreshFlow#refresh(de.cuioss.sheriff.token.client.discovery.ProviderMetadata, String,
 * java.util.function.Consumer)} and {@link RefreshRedemption#rotationUnknown()}.
 * <p>
 * It extends {@link TransportException} so every existing caller and every documented
 * {@code @throws TransportException} contract keeps holding unchanged; only a caller that needs the
 * pre-/post-redemption distinction catches this narrower type.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class RedeemedResponseException extends TransportException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param message the caller-safe detail message
     */
    public RedeemedResponseException(String message) {
        super(message);
    }

    /**
     * @param message the caller-safe detail message
     * @param cause   the underlying cause
     */
    public RedeemedResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
