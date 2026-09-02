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
package de.cuioss.sheriff.token.client.lifecycle;

import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * The server-side token bundle held for a single session ({@code CLIENT-18} / {@code CLIENT-19}).
 * <p>
 * A stored token keeps the retrieved token material off the browser: the access token, the optional
 * refresh token and ID token, the optional sender-constraint {@link ConstraintBinding} (from the
 * DPoP/mTLS sender-constraint), and the access-token expiry. Carrying the {@code ConstraintBinding} here is
 * what lets the sender-constraint survive storage and proactive refresh.
 * <p>
 * <strong>Refresh is proof-driven, not metadata-only.</strong> {@link #refreshed} does <em>not</em>
 * blindly copy the stored binding forward — that would let a sender-constrained session silently
 * degrade to a plain bearer token if the authorization server returned one on refresh. Instead the
 * caller passes the {@code cnf} binding actually confirmed on the <em>refreshed</em> token, and a
 * previously sender-constrained bundle refuses the refresh unless that binding still confirms the same
 * key ({@code CLIENT-18}). A downgrade to bearer, or a re-binding to a different key, fails closed.
 * <p>
 * <strong>The refreshed identity is bound to the session.</strong> Alongside the sender-constraint, the
 * bundle carries the {@code subject} the session was established for. {@link #refreshed} refuses a
 * refresh whose refreshed principal is not the stored one, so a refresh can rotate credentials but can
 * never silently re-point a live session at a different user. The comparison is constant-time. A bundle
 * stored with a {@code null} subject (the principal was not yet known) skips the check and adopts the
 * refreshed subject, so the binding takes effect from the first refresh that names a principal.
 * <p>
 * The value object is immutable; a refresh produces a new {@code StoredToken} rather than mutating
 * shared state, so concurrent flows over the same session never observe a half-updated bundle.
 *
 * @param accessToken       the raw access token; never {@code null} or blank
 * @param refreshToken      the raw refresh token, or {@code null} when none was issued
 * @param idToken           the raw OpenID Connect ID token, or {@code null} when none was issued
 * @param constraintBinding the sender-constraint binding, or {@code null} for a bearer token
 * @param expiresAt         the access-token expiry instant, or {@code null} when unknown
 * @param subject           the principal the session is bound to, or {@code null} when the principal
 *                          was not known at storage time
 * @since 1.0
 * @author Oliver Wolff
 */
public record StoredToken(String accessToken, @Nullable String refreshToken, @Nullable String idToken,
@Nullable ConstraintBinding constraintBinding, @Nullable Instant expiresAt,
@Nullable String subject) {

    /**
     * @param accessToken       the raw access token; must not be {@code null} or blank
     * @param refreshToken      the raw refresh token, or {@code null}
     * @param idToken           the raw ID token, or {@code null}
     * @param constraintBinding the sender-constraint binding, or {@code null}
     * @param expiresAt         the access-token expiry, or {@code null}
     * @param subject           the bound principal, or {@code null}
     */
    public StoredToken {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
    }

    /**
     * @return the sender-constraint binding, if the token is sender-constrained
     */
    public Optional<ConstraintBinding> binding() {
        return Optional.ofNullable(constraintBinding);
    }

    /**
     * @param now the reference instant
     * @return whether the access token has expired at {@code now} (never expired when the expiry is
     *         unknown)
     */
    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        return expiresAt != null && !now.isBefore(expiresAt);
    }

    /**
     * Produces the successor bundle after a refresh, keeping the current ID token and recording the
     * sender-constraint the <em>refreshed</em> token was actually issued under.
     * <p>
     * This overload preserves the stored ID token; it is the correct call when the AS omitted an ID
     * token on the refresh (OIDC Core §12.2 makes it optional). When the AS <em>did</em> return a
     * refreshed ID token, use
     * {@link #refreshed(String, String, Instant, ConstraintBinding, String, String)} so the successor
     * carries the new, consistency-checked ID token rather than the stale one.
     *
     * @param newAccessToken   the refreshed access token; must not be {@code null} or blank
     * @param newRefreshToken  the refreshed refresh token, or {@code null} to keep the current one
     * @param newExpiresAt     the refreshed access-token expiry, or {@code null} when unknown
     * @param refreshedBinding the {@code cnf} sender-constraint confirmed on the refreshed token, or
     *                         {@code null} when the refreshed token is a plain bearer token
     * @param refreshedSubject the principal the refreshed token names, or {@code null} when the
     *                         refreshed token carries no subject
     * @return the refreshed bundle recording the verified binding and keeping the current ID token
     * @throws IllegalStateException if this bundle was sender-constrained but {@code refreshedBinding}
     *         no longer confirms the same key (a downgrade or re-binding), or if this bundle is bound to
     *         a subject that {@code refreshedSubject} does not match
     */
    public StoredToken refreshed(String newAccessToken, @Nullable String newRefreshToken,
            @Nullable Instant newExpiresAt, @Nullable ConstraintBinding refreshedBinding,
            @Nullable String refreshedSubject) {
        return refreshed(newAccessToken, newRefreshToken, newExpiresAt, refreshedBinding, refreshedSubject,
                null);
    }

    /**
     * Produces the successor bundle after a refresh, recording the sender-constraint the
     * <em>refreshed</em> token was actually issued under and carrying the supplied ID token.
     * <p>
     * When this bundle was sender-constrained, the refresh is refused unless {@code refreshedBinding}
     * still confirms the same key: a {@code null} {@code refreshedBinding} (the AS issued a plain
     * bearer token) or a binding to a different key is a downgrade and fails closed with an
     * {@link IllegalStateException}, rather than copying the stale binding onto a token that no longer
     * carries it. When this bundle was an unconstrained bearer token, the successor simply records
     * whatever binding the refreshed token carries.
     * <p>
     * {@code newIdToken} carries the ID token the AS actually returned on the refresh, already checked
     * for {@code iss}/{@code sub} consistency by the caller (OIDC Core §12.2). A {@code null}
     * {@code newIdToken} means the AS omitted an ID token on the refresh, so the current ID token is
     * kept.
     * <p>
     * {@code refreshedSubject} carries the principal the refreshed token names. When this bundle is
     * already bound to a subject, the refresh is refused unless {@code refreshedSubject} is that same
     * principal — a differing principal, or an absent one on a bound session, fails closed rather than
     * re-pointing a live session at another user. When this bundle carries no subject yet, the
     * successor adopts {@code refreshedSubject} and is bound from then on.
     *
     * @param newAccessToken   the refreshed access token; must not be {@code null} or blank
     * @param newRefreshToken  the refreshed refresh token, or {@code null} to keep the current one
     * @param newExpiresAt     the refreshed access-token expiry, or {@code null} when unknown
     * @param refreshedBinding the {@code cnf} sender-constraint confirmed on the refreshed token, or
     *                         {@code null} when the refreshed token is a plain bearer token
     * @param refreshedSubject the principal the refreshed token names, or {@code null} when the
     *                         refreshed token carries no subject
     * @param newIdToken       the refreshed, consistency-checked ID token, or {@code null} to keep the
     *                         current one when the AS omitted it on the refresh
     * @return the refreshed bundle recording the verified binding, the bound subject, and the effective
     *         ID token
     * @throws IllegalStateException if this bundle was sender-constrained but {@code refreshedBinding}
     *         no longer confirms the same key (a downgrade or re-binding), or if this bundle is bound to
     *         a subject that {@code refreshedSubject} does not match
     */
    public StoredToken refreshed(String newAccessToken, @Nullable String newRefreshToken,
            @Nullable Instant newExpiresAt, @Nullable ConstraintBinding refreshedBinding,
            @Nullable String refreshedSubject, @Nullable String newIdToken) {
        if (constraintBinding != null && !constraintBinding.equals(refreshedBinding)) {
            throw new IllegalStateException(
                    "refreshed token is no longer bound to the stored sender-constraint key; "
                            + "refusing to preserve a stale cnf binding on a downgraded token");
        }
        if (subject != null && !subjectsMatch(subject, refreshedSubject)) {
            throw new IllegalStateException(
                    "refreshed token names a different principal than the session is bound to; "
                            + "refusing to re-point a live session at another subject");
        }
        return new StoredToken(newAccessToken,
                newRefreshToken != null ? newRefreshToken : refreshToken,
                newIdToken != null ? newIdToken : idToken, refreshedBinding, newExpiresAt,
                refreshedSubject != null ? refreshedSubject : subject);
    }

    /**
     * Constant-time subject comparison, matching the {@code SubBindingValidator} idiom: the digest
     * comparison does not short-circuit on the first differing byte, so the check leaks no information
     * about how much of a guessed principal was correct. An absent {@code refreshedSubject} never
     * matches — a bound session refuses a refresh that names no principal.
     */
    private static boolean subjectsMatch(String storedSubject, @Nullable String refreshedSubject) {
        return refreshedSubject != null && MessageDigest.isEqual(
                storedSubject.getBytes(StandardCharsets.UTF_8),
                refreshedSubject.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Renders the bundle without exposing live token material: the access, refresh, and ID tokens are
     * redacted so a stray {@code toString()} — a log statement, an exception message, or a debugger
     * dump — never leaks a usable credential (H8). Only credential presence and the non-secret fields
     * are shown.
     * <p>
     * The bound {@code subject} is not a credential, so it is not redacted; it <em>is</em>
     * session-identifying, so it is rendered as a stable, non-reversible correlation hash rather than
     * the raw principal. Two renderings of the same session therefore still correlate without the
     * principal ever appearing in plain text.
     *
     * @return a redacted string representation carrying no live token material and no plain principal
     */
    @Override
    public String toString() {
        return "StoredToken[accessToken=<redacted>, refreshToken=" + redact(refreshToken)
                + ", idToken=" + redact(idToken) + ", constraintBinding=" + constraintBinding
                + ", expiresAt=" + expiresAt + ", subject=" + mask(subject) + "]";
    }

    private static String redact(@Nullable String secret) {
        return secret == null ? "null" : "<redacted>";
    }

    /**
     * Masks a session-identifying value for rendering: returns the first 8 hex characters of its
     * SHA-256 digest, matching the session-identifier masking used on the lifecycle-logging path.
     */
    private static String mask(@Nullable String identifying) {
        if (identifying == null) {
            return "null";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(identifying.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 4);
        } catch (NoSuchAlgorithmException e) {
            return "********";
        }
    }
}
