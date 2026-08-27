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

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * The per-flow secret state that binds an interactive {@code authorization_code} request to its
 * callback: the {@code state} CSRF binding ({@code CLIENT-5}) and the {@code nonce} ID-token
 * binding ({@code CLIENT-6}).
 * <p>
 * A context is created when the authorization request is built and must be retained by the
 * relying party (bound to the user's session) until the callback returns. It carries:
 * <ul>
 *   <li>{@code state} — the CSRF token echoed back and checked at the callback;</li>
 *   <li>{@code nonce} — the value bound into the ID token to defend against replay;</li>
 *   <li>the {@link PkceChallenge} — whose secret verifier is redeemed at the token endpoint;</li>
 *   <li>the exact {@code redirect_uri} the request was issued for;</li>
 *   <li>an optional {@code acr_values} request for RFC 9470 step-up.</li>
 * </ul>
 * The context is immutable; {@code state}, {@code nonce}, and the PKCE verifier are secrets and are
 * never logged.
 * <p>
 * <strong>One-time-use discard contract (L7):</strong> a context is single-use. The relying party
 * MUST bind exactly one context to the request it was created for, and MUST discard it — remove it
 * from the session store — as soon as the callback has been processed (whether the exchange succeeded
 * or {@link CallbackHandler} rejected it). Because the type carries no consumed flag, re-presenting a
 * retained context against a second callback would re-run the {@code state}/{@code nonce} checks
 * against the same secrets and defeat the anti-CSRF/anti-replay guarantees; the class stays immutable
 * and the one-time-use invariant is enforced by the caller's discard, not by internal mutation.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class FlowContext {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();
    private static final int TOKEN_ENTROPY_BYTES = 32;

    private final String state;
    private final String nonce;
    private final String redirectUri;
    private final PkceChallenge pkceChallenge;
    private final @Nullable String acrValues;
    private final @Nullable Integer maxAge;

    private FlowContext(String state, String nonce, String redirectUri, PkceChallenge pkceChallenge,
            @Nullable String acrValues, @Nullable Integer maxAge) {
        this.state = state;
        this.nonce = nonce;
        this.redirectUri = redirectUri;
        this.pkceChallenge = pkceChallenge;
        this.acrValues = acrValues;
        this.maxAge = maxAge;
    }

    /**
     * Creates a context for a standard interactive authorization request, generating a fresh
     * {@code state}, {@code nonce}, and PKCE challenge.
     *
     * @param redirectUri the exact registered redirect URI; must not be {@code null} or blank
     * @return a new flow context
     */
    public static FlowContext create(String redirectUri) {
        return create(redirectUri, null, null);
    }

    /**
     * Creates a context that additionally requests the given {@code acr_values} (RFC 9470 step-up).
     *
     * @param redirectUri the exact registered redirect URI; must not be {@code null} or blank
     * @param acrValues   the requested authentication context class values, or {@code null} for none
     * @return a new flow context
     */
    public static FlowContext create(String redirectUri, @Nullable String acrValues) {
        return create(redirectUri, acrValues, null);
    }

    /**
     * Creates a context that requests the given {@code acr_values} and {@code max_age} freshness
     * constraint (RFC 9470 step-up).
     *
     * @param redirectUri the exact registered redirect URI; must not be {@code null} or blank
     * @param acrValues   the requested authentication context class values, or {@code null} for none
     * @param maxAge      the maximum authentication age in seconds, or {@code null} for none
     * @return a new flow context
     */
    public static FlowContext create(String redirectUri, @Nullable String acrValues, @Nullable Integer maxAge) {
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        if (redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri must not be blank");
        }
        return new FlowContext(randomToken(), randomToken(), redirectUri, PkceChallenge.generate(), acrValues, maxAge);
    }

    /**
     * @return the CSRF {@code state} token
     */
    public String state() {
        return state;
    }

    /**
     * @return the {@code nonce} bound into the ID token
     */
    public String nonce() {
        return nonce;
    }

    /**
     * @return the exact redirect URI this request was issued for
     */
    public String redirectUri() {
        return redirectUri;
    }

    /**
     * @return the PKCE challenge/verifier pair
     */
    public PkceChallenge pkceChallenge() {
        return pkceChallenge;
    }

    /**
     * @return the requested {@code acr_values}, if step-up was requested
     */
    public Optional<String> acrValues() {
        return Optional.ofNullable(acrValues);
    }

    /**
     * @return the requested {@code max_age} freshness constraint in seconds, if step-up requested it
     */
    public Optional<Integer> maxAge() {
        return Optional.ofNullable(maxAge);
    }

    private static String randomToken() {
        byte[] entropy = new byte[TOKEN_ENTROPY_BYTES];
        SECURE_RANDOM.nextBytes(entropy);
        return BASE64_URL.encodeToString(entropy);
    }
}
