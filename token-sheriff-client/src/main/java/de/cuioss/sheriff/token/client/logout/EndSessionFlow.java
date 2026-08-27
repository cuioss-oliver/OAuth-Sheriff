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
package de.cuioss.sheriff.token.client.logout;

import de.cuioss.sheriff.token.client.internal.FormEncoder;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Builds the front-channel RP-initiated logout request to the OpenID Connect
 * {@code end_session_endpoint} ({@code CLIENT-13}).
 * <p>
 * The request always carries three security-relevant parameters, and refuses to build without them:
 * <ul>
 *   <li>{@code id_token_hint} — the ID token identifying the session to end; a logout without it is
 *       refused (an unauthenticated logout is a CSRF/DoS surface).</li>
 *   <li>{@code post_logout_redirect_uri} — validated by exact match through
 *       {@link PostLogoutRedirectValidator}, so an unmatched URI can never be used (open-redirect
 *       defence).</li>
 *   <li>{@code state} — a session-bound CSRF token echoed back on the post-logout redirect; a logout
 *       without it is refused.</li>
 * </ul>
 * A complete logout also revokes the session's held tokens: the relying party clears them via
 * {@link de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager#revokeAndClear(String)}
 * (fail-closed, no stale-read) and revokes them at the AS through
 * {@link de.cuioss.sheriff.token.client.lifecycle.RevocationClient} before redirecting to the URL this
 * flow builds ({@code T-LOGOUT}). This class only constructs the front-channel redirect; it issues no
 * HTTP itself.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect RP-Initiated Logout 1.0</a>
 */
public class EndSessionFlow {

    private static final String PARAM_ID_TOKEN_HINT = "id_token_hint";
    private static final String PARAM_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    private static final String PARAM_STATE = "state";

    private final PostLogoutRedirectValidator redirectValidator;

    /**
     * @param redirectValidator the exact-match post-logout redirect validator; must not be {@code null}
     */
    public EndSessionFlow(PostLogoutRedirectValidator redirectValidator) {
        this.redirectValidator = Objects.requireNonNull(redirectValidator, "redirectValidator must not be null");
    }

    /**
     * Builds the RP-initiated logout redirect URL, failing closed on any missing security parameter or
     * an unregistered post-logout redirect URI.
     *
     * @param endSessionEndpoint      the absolute {@code end_session_endpoint} (from discovery); must
     *                                not be {@code null} or blank
     * @param idTokenHint             the ID token identifying the session; must not be {@code null} or
     *                                blank
     * @param postLogoutRedirectUri   the post-logout redirect URI; must exactly match a registered URI
     * @param state                   the session-bound CSRF state; must not be {@code null} or blank
     * @return the fully-formed end-session redirect URL
     * @throws IllegalArgumentException if any required parameter is {@code null} or blank
     * @throws de.cuioss.sheriff.token.commons.error.ClientProtocolException if the post-logout redirect
     *                                  URI is not exactly registered
     */
    public String buildLogoutRedirect(String endSessionEndpoint, String idTokenHint,
            String postLogoutRedirectUri, String state) {
        requireNonBlank(endSessionEndpoint, "endSessionEndpoint");
        requireNonBlank(idTokenHint, PARAM_ID_TOKEN_HINT);
        requireNonBlank(state, PARAM_STATE);
        String validatedRedirect = redirectValidator.validate(postLogoutRedirectUri);

        Map<String, String> params = new HashMap<>(Map.of(
                PARAM_ID_TOKEN_HINT, idTokenHint,
                PARAM_POST_LOGOUT_REDIRECT_URI, validatedRedirect,
                PARAM_STATE, state));

        return endSessionEndpoint + (endSessionEndpoint.indexOf('?') < 0 ? '?' : '&') + FormEncoder.encode(params);
    }

    /**
     * Verifies the {@code state} echoed on the post-logout redirect against the session-bound state
     * the client sent on the end-session request — the RP-initiated-logout CSRF check (M2).
     * <p>
     * {@link #buildLogoutRedirect} sends a {@code state}, but a state that is never checked on the way
     * back provides no protection: an attacker-forged post-logout redirect could drive the relying
     * party's post-logout cleanup. This seam closes that gap. A blank or mismatched echoed state fails
     * closed; the comparison is constant-time so it does not leak the expected state through timing.
     *
     * @param expectedState the session-bound {@code state} the client sent on the logout request; must
     *                      not be {@code null} or blank
     * @param returnedState the {@code state} echoed on the post-logout redirect; a {@code null}, blank,
     *                      or non-matching value is rejected
     * @throws IllegalArgumentException if {@code expectedState} is {@code null} or blank
     * @throws IllegalStateException    if the echoed state is absent, blank, or does not match
     */
    public void verifyPostLogoutState(String expectedState, @Nullable String returnedState) {
        requireNonBlank(expectedState, PARAM_STATE);
        if (returnedState == null || returnedState.isBlank()
                || !MessageDigest.isEqual(expectedState.getBytes(StandardCharsets.UTF_8),
                returnedState.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalStateException("post-logout 'state' does not match the session state");
        }
    }

    private static void requireNonBlank(String value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
