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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.RefreshTokenFamily;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Orchestrates the server-side token lifecycle over a {@link TokenStore}: store, retrieve, proactive
 * refresh, and revoke-and-clear on logout ({@code CLIENT-17} / {@code CLIENT-18} / {@code CLIENT-19}).
 * <p>
 * Refresh is sender-constraint aware but proof-driven, not metadata-only: {@link #applyRefresh} takes
 * the {@code cnf} binding actually confirmed on the refreshed token and verifies it against the stored
 * {@link StoredToken#binding() ConstraintBinding} (via {@link StoredToken#refreshed}), so a
 * proactively-refreshed token that came back as a plain bearer — or bound to a different key — is
 * rejected as a downgrade rather than silently keeping the stale binding ({@code CLIENT-18}).
 * <p>
 * <strong>Refresh is identity-bound as well as constraint-bound.</strong> Alongside that downgrade
 * refusal, {@link #applyRefresh} carries the principal the refreshed access token names and
 * {@link StoredToken#refreshed} refuses the refresh when a session already bound to a subject is handed
 * a different one — so a refresh rotates credentials but never re-points a live session at another
 * user. Both checks run inside the same atomic transform, so neither opens a check-then-act window.
 * <p>
 * <strong>Logout is fail-closed with no stale-read window.</strong> {@link #revokeAndClear} performs a
 * single atomic take-and-clear via {@link TokenStore#remove(String)}: after it returns, the session's
 * tokens are already gone from the store, so any concurrent {@link #get} sees nothing and a stale
 * token can no longer be used through the store. The returned bundle is handed back so the relying
 * party revokes it at the authorization server (RFC 7009, via
 * {@link RevocationClient}) — the store clear (client-side fail-closed) and the AS revocation
 * (server-side invalidation) together defend {@code T-LOGOUT} / {@code T-REFRESH-THEFT}.
 * <p>
 * <strong>Refresh is reuse-detecting, single-flight, and ID-token-consistent.</strong>
 * {@link #refresh} drives the whole rotation for a session: it presents the stored refresh token
 * through {@link RefreshFlow}, routes the rotation through the session's
 * {@link RefreshTokenFamily}, and on a detected reuse of a superseded token revokes the family at the
 * authorization server (RFC 7009) and clears the store fail-closed ({@code CLIENT-5}). A
 * per-session single-flight collapses a concurrent proactive refresh onto one in-flight rotation, so
 * a benign race never redeems the same token twice and self-classifies as reuse. A refreshed ID token
 * is verified for OIDC Core §12.2 {@code iss}/{@code sub} consistency against the refreshed access
 * token and carried forward, rather than silently preserving the pre-refresh ID token.
 * <p>
 * The session&rarr;family mapping is held in-memory (matching the default {@link InMemoryTokenStore}
 * posture); a relying party that runs a persistent, shared {@link TokenStore} across instances would
 * pair it with a persistent family store — that SPI is not yet provided.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009 - OAuth 2.0 Token Revocation</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OIDC Core §12.2</a>
 */
public class TokenLifecycleManager {

    private static final CuiLogger LOGGER = new CuiLogger(TokenLifecycleManager.class);

    private static final String REFRESH_TOKEN_TYPE_HINT = "refresh_token";

    /**
     * Upper bound on the number of tracked rotation families. A session that expires without an
     * explicit logout (e.g. {@link TokenStore} eviction or timeout) never reaches
     * {@link #revokeAndClear}, so its family entry is not removed on the logout path; the bounded
     * LRU below evicts the least-recently-used family once this cap is exceeded, so {@link #families}
     * cannot grow without limit. The cap is deliberately generous (well above any realistic
     * concurrent-session count for an in-memory posture) so eviction only ever reclaims families
     * whose sessions are long dead.
     */
    private static final int MAX_TRACKED_FAMILIES = 10_000;

    private final TokenStore tokenStore;
    private final RefreshScheduler refreshScheduler;

    /**
     * Per-session refresh-token rotation families. Seeded on {@link #store} when a refresh token is
     * present and removed on {@link #revokeAndClear}, so a superseded-token replay against a
     * still-live session is detected as reuse.
     * <p>
     * Backed by an access-ordered, size-capped LRU (a {@link LinkedHashMap} in {@code accessOrder}
     * mode wrapped for thread-safety) rather than an unbounded map: a session that expires without an
     * explicit logout never removes its family via {@link #revokeAndClear}, so an unbounded map would
     * leak those entries forever. Capping at {@link #MAX_TRACKED_FAMILIES} evicts the least-recently
     * used family — one whose session has been idle longest — without touching the reuse-detection or
     * single-flight semantics, which continue to key off the per-session entry while it is live.
     */
    private final Map<String, RefreshTokenFamily> families = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Serial
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, RefreshTokenFamily> eldest) {
                    return size() > MAX_TRACKED_FAMILIES;
                }
            });

    /**
     * Per-session in-flight rotations. The first caller to start a refresh for a session installs its
     * future here; a concurrent caller shares that single result instead of redeeming the same token
     * again (the {@code H6} single-flight spanning redeem + apply).
     */
    private final ConcurrentMap<String, CompletableFuture<Optional<StoredToken>>> inFlight =
            new ConcurrentHashMap<>();

    /**
     * @param tokenStore       the backing token store; must not be {@code null}
     * @param refreshScheduler the proactive-refresh policy; must not be {@code null}
     */
    public TokenLifecycleManager(TokenStore tokenStore, RefreshScheduler refreshScheduler) {
        this.tokenStore = Objects.requireNonNull(tokenStore, "tokenStore must not be null");
        this.refreshScheduler = Objects.requireNonNull(refreshScheduler, "refreshScheduler must not be null");
    }

    /**
     * Stores (or replaces) the token bundle for a session.
     * <p>
     * When the bundle carries a refresh token and no rotation family yet tracks the session, a family
     * is seeded with that token so a later replay of a superseded token is detected as reuse. An
     * existing family is left intact — re-storing an <em>older</em> bundle for a live session does not
     * roll the family back, so the stale refresh token is still recognised as superseded.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @param token     the token bundle; must not be {@code null}
     */
    public void store(String sessionId, StoredToken token) {
        tokenStore.store(sessionId, token);
        String refreshToken = token.refreshToken();
        if (refreshToken != null && !refreshToken.isBlank()) {
            families.computeIfAbsent(sessionId, key -> new RefreshTokenFamily(refreshToken));
        }
    }

    /**
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @return the stored bundle, or {@link Optional#empty()} when none is held
     */
    public Optional<StoredToken> get(String sessionId) {
        return tokenStore.retrieve(sessionId);
    }

    /**
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @param now       the reference instant; must not be {@code null}
     * @return whether the session's access token is inside its proactive-refresh window (false when no
     *         token is held or the expiry is unknown)
     */
    public boolean needsRefresh(String sessionId, Instant now) {
        return get(sessionId).map(token -> refreshScheduler.needsRefresh(token, now)).orElse(false);
    }

    /**
     * Applies refreshed token material to a stored session, carrying the ID token forward and
     * verifying the refreshed token's sender-constraint and principal against the stored ones
     * ({@code CLIENT-18}). Does nothing and returns empty when no bundle is held. When the stored
     * bundle was sender-constrained but {@code refreshedBinding} no longer confirms the same key, or
     * when the stored bundle is bound to a subject that {@code refreshedSubject} does not match, the
     * transform throws {@link IllegalStateException} rather than writing a mismatched bundle.
     *
     * @param sessionId        the opaque session identifier; must not be {@code null} or blank
     * @param newAccessToken   the refreshed access token; must not be {@code null} or blank
     * @param newRefreshToken  the refreshed refresh token, or {@code null} to keep the current one
     * @param newExpiresAt     the refreshed access-token expiry, or {@code null} when unknown
     * @param refreshedBinding the {@code cnf} binding confirmed on the refreshed token, or {@code null}
     *                         when the refreshed token is a plain bearer token
     * @param refreshedSubject the principal the refreshed access token names, or {@code null} when it
     *                         carries no subject
     * @return the updated stored bundle, or {@link Optional#empty()} when no bundle was held
     */
    public Optional<StoredToken> applyRefresh(String sessionId, String newAccessToken,
            @Nullable String newRefreshToken, @Nullable Instant newExpiresAt,
            @Nullable ConstraintBinding refreshedBinding, @Nullable String refreshedSubject) {
        return applyRefresh(sessionId, newAccessToken, newRefreshToken, newExpiresAt, refreshedBinding,
                refreshedSubject, null);
    }

    /**
     * Applies refreshed token material to a stored session, carrying the supplied refreshed ID token
     * (OIDC Core §12.2) and verifying the refreshed token's sender-constraint and principal against the
     * stored ones ({@code CLIENT-18}). Does nothing and returns empty when no bundle is held.
     *
     * @param sessionId        the opaque session identifier; must not be {@code null} or blank
     * @param newAccessToken   the refreshed access token; must not be {@code null} or blank
     * @param newRefreshToken  the refreshed refresh token, or {@code null} to keep the current one
     * @param newExpiresAt     the refreshed access-token expiry, or {@code null} when unknown
     * @param refreshedBinding the {@code cnf} binding confirmed on the refreshed token, or {@code null}
     *                         when the refreshed token is a plain bearer token
     * @param refreshedSubject the principal the refreshed access token names, or {@code null} when it
     *                         carries no subject
     * @param newIdToken       the refreshed, consistency-checked ID token, or {@code null} to keep the
     *                         current one when the AS omitted it on the refresh
     * @return the updated stored bundle, or {@link Optional#empty()} when no bundle was held
     */
    public Optional<StoredToken> applyRefresh(String sessionId, String newAccessToken,
            @Nullable String newRefreshToken, @Nullable Instant newExpiresAt,
            @Nullable ConstraintBinding refreshedBinding, @Nullable String refreshedSubject,
            @Nullable String newIdToken) {
        // Atomic retrieve-transform-store: a concurrent revokeAndClear (logout) can no longer slip
        // between the read and the write and resurrect a just-revoked session, so a refresh applied
        // after logout is a no-op rather than a stale-token write (CLIENT-22). The subject binding is
        // checked inside the same transform for the same reason: comparing here, before the update,
        // would reopen the check-then-act window the atomic update exists to close.
        return tokenStore.update(sessionId,
                current -> current.refreshed(newAccessToken, newRefreshToken, newExpiresAt, refreshedBinding,
                        refreshedSubject, newIdToken));
    }

    /**
     * Drives a full, reuse-detecting, single-flight refresh for a session ({@code CLIENT-5} /
     * {@code CLIENT-22}, OIDC Core §12.2).
     * <p>
     * The stored refresh token is presented through {@code refreshFlow}; when the AS rotates it, the
     * rotation is routed through the session's {@link RefreshTokenFamily}. A presented token the
     * family knows to be superseded is a reuse: the family is revoked at the authorization server via
     * {@code revocationClient} (RFC 7009), the store is cleared fail-closed, and the reuse is
     * re-thrown. A concurrent proactive refresh for the same session shares the single in-flight
     * rotation rather than redeeming the token twice, so a benign race never self-classifies as reuse.
     * A refreshed ID token is verified for §12.2 {@code iss}/{@code sub} consistency against the
     * refreshed access token before it is carried forward.
     * <p>
     * This coordinator refreshes plain-bearer sessions; it applies the refreshed material with no
     * {@code cnf} binding, so a sender-constrained stored bundle fails closed (a downgrade rather than
     * a silent bearer refresh) — sender-constrained refresh is applied through
     * {@link #applyRefresh(String, String, String, Instant, ConstraintBinding, String, String)} with
     * the confirmed binding.
     * <p>
     * The refreshed principal is read from the validated refreshed access token and handed to the
     * transform, so a session already bound to a subject refuses a refresh naming a different one.
     *
     * @param sessionId               the opaque session identifier; must not be {@code null} or blank
     * @param metadata                the resolved provider metadata (token + revocation endpoints);
     *                                must not be {@code null}
     * @param refreshFlow             the refresh-token exchange; must not be {@code null}
     * @param revocationClient        the RFC 7009 revocation client used on detected reuse; must not be
     *                                {@code null}
     * @param idTokenValidationBridge the ID-token validation bridge for the §12.2 consistency check;
     *                                must not be {@code null}
     * @param clientAuthentication    the client authentication to present on revocation; must not be
     *                                {@code null}
     * @return the refreshed stored bundle, or {@link Optional#empty()} when no refreshable bundle is
     *         held
     * @throws de.cuioss.sheriff.token.commons.error.ClientProtocolException if refresh-token reuse is
     *                               detected (the family is revoked and the store cleared first)
     * @throws IllegalStateException if the refreshed ID token is inconsistent with the refreshed
     *                               access token, or if the refreshed access token names a principal
     *                               other than the one the session is bound to
     */
    public Optional<StoredToken> refresh(String sessionId, ProviderMetadata metadata,
            RefreshFlow refreshFlow, RevocationClient revocationClient,
            IdTokenValidationBridge idTokenValidationBridge, ClientAuthentication clientAuthentication) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(refreshFlow, "refreshFlow must not be null");
        Objects.requireNonNull(revocationClient, "revocationClient must not be null");
        Objects.requireNonNull(idTokenValidationBridge, "idTokenValidationBridge must not be null");
        Objects.requireNonNull(clientAuthentication, "clientAuthentication must not be null");

        CompletableFuture<Optional<StoredToken>> mine = new CompletableFuture<>();
        CompletableFuture<Optional<StoredToken>> alreadyInFlight = inFlight.putIfAbsent(sessionId, mine);
        if (alreadyInFlight != null) {
            return awaitInFlight(alreadyInFlight);
        }
        try {
            Optional<StoredToken> refreshed = doRefresh(sessionId, metadata, refreshFlow, revocationClient,
                    idTokenValidationBridge, clientAuthentication);
            mine.complete(refreshed);
            return refreshed;
        } /*~~(TODO: Catch specific not RuntimeException. Suppress: // cui-rewrite:disable InvalidExceptionUsageRecipe)~~>*/ catch (RuntimeException failure) {
            mine.completeExceptionally(failure);
            throw failure;
        } finally {
            inFlight.remove(sessionId, mine);
        }
    }

    private Optional<StoredToken> doRefresh(String sessionId, ProviderMetadata metadata,
            RefreshFlow refreshFlow, RevocationClient revocationClient,
            IdTokenValidationBridge idTokenValidationBridge, ClientAuthentication clientAuthentication) {
        Optional<StoredToken> held = tokenStore.retrieve(sessionId);
        if (held.isEmpty()) {
            return Optional.empty();
        }
        String presentedRefreshToken = held.get().refreshToken();
        if (presentedRefreshToken == null || presentedRefreshToken.isBlank()) {
            return Optional.empty();
        }

        RotationResult rotation = refreshFlow.refresh(metadata, presentedRefreshToken);

        // OIDC Core §12.2 consistency is checked BEFORE the family is advanced: an inconsistent
        // refreshed ID token must be refused without mutating the rotation family or the store, so a
        // later legitimate refresh is not poisoned into a false-reuse by a half-applied rotation.
        String refreshedIdToken = verifiedRefreshedIdToken(rotation, idTokenValidationBridge);

        if (rotation.rotated()) {
            RefreshTokenFamily family = families.computeIfAbsent(sessionId,
                    key -> new RefreshTokenFamily(presentedRefreshToken));
            try {
                family.rotate(presentedRefreshToken, rotation.refreshToken());
            } catch (ClientProtocolException reuse) {
                revokeReusedFamily(sessionId, metadata, presentedRefreshToken, revocationClient,
                        clientAuthentication);
                throw reuse;
            }
        }

        Instant refreshedExpiry = rotation.accessTokenExpiresInSeconds() > 0
                ? Instant.now().plusSeconds(rotation.accessTokenExpiresInSeconds())
                : null;

        // The principal the refreshed access token names, handed to the transform so a session already
        // bound to a subject refuses a refresh that names a different one. It is read from the same
        // validated access token the §12.2 consistency check above uses.
        String refreshedSubject = rotation.accessToken().getSubject().orElse(null);

        return applyRefresh(sessionId, rotation.accessToken().getRawToken(), rotation.refreshToken(),
                refreshedExpiry, null, refreshedSubject, refreshedIdToken);
    }

    private void revokeReusedFamily(String sessionId, ProviderMetadata metadata, String reusedToken,
            RevocationClient revocationClient, ClientAuthentication clientAuthentication) {
        LOGGER.warn(ClientLogMessages.WARN.REFRESH_REUSE_REVOCATION, maskSessionId(sessionId));
        metadata.getRevocationEndpoint().ifPresent(endpoint -> {
            try {
                revocationClient.revoke(endpoint, reusedToken, REFRESH_TOKEN_TYPE_HINT, clientAuthentication);
            } /*~~(TODO: Catch specific not RuntimeException. Suppress: // cui-rewrite:disable InvalidExceptionUsageRecipe)~~>*/ catch (RuntimeException revocationFailure) {
                // Revocation is best-effort: a failed AS revocation must not stop the client-side
                // fail-closed store clear below, nor mask the reuse signal to the caller.
                LOGGER.debug(revocationFailure, "RFC 7009 revocation on detected reuse failed: %s",
                        revocationFailure.getMessage());
            }
        });
        tokenStore.remove(sessionId);
        families.remove(sessionId);
    }

    /**
     * Verifies a refreshed ID token against the refreshed access token (OIDC Core §12.2) and returns
     * the ID token to carry forward, or {@code null} when the AS omitted one on the refresh.
     */
    @Nullable
    private static String verifiedRefreshedIdToken(RotationResult rotation,
            IdTokenValidationBridge idTokenValidationBridge) {
        String rawIdToken = rotation.idToken();
        if (rawIdToken == null || rawIdToken.isBlank()) {
            return null;
        }
        IdTokenContent refreshedIdToken = idTokenValidationBridge.validateRefreshedIdToken(rawIdToken);
        if (!consistentWithAccessToken(rotation.accessToken(), refreshedIdToken)) {
            LOGGER.warn(ClientLogMessages.WARN.REFRESHED_ID_TOKEN_INCONSISTENT);
            throw new IllegalStateException(
                    "refreshed ID token is inconsistent with the refreshed access token (OIDC Core §12.2)");
        }
        return rawIdToken;
    }

    private static boolean consistentWithAccessToken(AccessTokenContent accessToken, IdTokenContent idToken) {
        if (!accessToken.getIssuer().equals(idToken.getIssuer())) {
            return false;
        }
        // 'sub' is mandatory on an OIDC ID token but optional on an access token: cross-check it only
        // when the access token actually carries a subject (§12.2 "the access token's sub").
        Optional<String> accessSubject = accessToken.getSubject();
        return accessSubject.isEmpty() || accessSubject.equals(idToken.getSubject());
    }

    private static Optional<StoredToken> awaitInFlight(
            CompletableFuture<Optional<StoredToken>> inFlightRotation) {
        try {
            return inFlightRotation.join();
        } catch (CompletionException completion) {
            if (completion.getCause() instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw completion;
        }
    }

    /**
     * Atomically clears the session's held tokens (fail-closed) and returns them so the relying party
     * can revoke them at the authorization server. After this call {@link #get(String)} for the same
     * session returns empty.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @return the cleared bundle to revoke at the AS, or {@link Optional#empty()} when none was held
     */
    public Optional<StoredToken> revokeAndClear(String sessionId) {
        Optional<StoredToken> removed = tokenStore.remove(sessionId);
        families.remove(sessionId);
        if (removed.isPresent()) {
            LOGGER.info(ClientLogMessages.INFO.LOGOUT_TOKENS_CLEARED, maskSessionId(sessionId));
        }
        return removed;
    }

    /**
     * Masks a session identifier for logging: session identification values must never appear in
     * logs unmasked, so this logs a stable, non-reversible correlation hash instead of the raw
     * identifier.
     *
     * @param sessionId the raw session identifier; must not be {@code null}
     * @return the first 8 hex characters of the SHA-256 digest of {@code sessionId}
     */
    private static String maskSessionId(String sessionId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sessionId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 4);
        } catch (NoSuchAlgorithmException e) {
            return "********";
        }
    }
}
