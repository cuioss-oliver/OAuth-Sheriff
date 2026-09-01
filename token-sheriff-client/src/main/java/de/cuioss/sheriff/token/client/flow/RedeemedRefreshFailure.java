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

/**
 * Implemented by every exception {@link RefreshFlow#refresh(
 * de.cuioss.sheriff.token.client.discovery.ProviderMetadata, String)} raises <em>after</em> the
 * authorization server has answered and therefore after it has redeemed the presented refresh token.
 * <p>
 * <strong>Why the signal rides on the exception.</strong> Several client-side checks run after the
 * {@code 2xx} — access-token validation and the strict scope-reconciliation refusal — and each of them
 * throws before a {@link de.cuioss.sheriff.token.client.token.RotationResult} exists. A caller holding
 * a session therefore cannot read rotation off a result and cannot tell from the exception type alone
 * whether the token it still has stored is alive or dead. Carrying the state on the thrown exception
 * closes that gap without a second, competing entry point into the flow: {@code refresh} stays the one
 * overridable method, so a subclass that intercepts it stays on the production path.
 * <p>
 * <strong>Absence is as meaningful as presence.</strong> A failure raised <em>before</em> the server
 * processed the request — a connection failure, a DNS failure, an SSRF-blocked target, or a non-success
 * HTTP status — does not implement this interface. That absence is what stops a transient network fault
 * from being mistaken for a burned credential and destroying a working session. Callers must classify
 * through {@link RefreshFlow#redemptionOf(Throwable)} rather than by listing exception types, so the
 * unparseable-{@code 2xx} case ({@link RedeemedResponseException}) is classified with the rest.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public interface RedeemedRefreshFailure {

    /**
     * @return what the authorization server did to the presented refresh token before this refusal was
     *         raised; never {@code null}
     */
    RefreshRedemption redemption();
}
