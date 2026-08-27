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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Decides when a stored access token should be proactively refreshed ({@code CLIENT-17}).
 * <p>
 * Short-lived access tokens are refreshed a little before they expire, so a request never carries an
 * already-expired token and there is no user-visible re-authentication. This is a pure policy object:
 * it computes <em>whether</em> a bundle is inside its refresh window; performing the refresh (and
 * preserving the sender-constraint across it) is {@link TokenLifecycleManager}'s job.
 * <p>
 * A token whose expiry is unknown ({@link StoredToken#expiresAt()} is {@code null}) is treated as
 * immediately refresh-eligible: with no basis to trust its remaining lifetime, the scheduler
 * refreshes it proactively rather than let an unknown-lifetime token live forever and risk
 * presenting a silently-expired token ({@code CLIENT-17}, L11).
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class RefreshScheduler {

    /** Default lead time before expiry at which a token becomes eligible for proactive refresh. */
    static final Duration DEFAULT_REFRESH_LEAD = Duration.ofSeconds(30);

    private final Duration refreshLead;

    /**
     * Creates a scheduler with the {@linkplain #DEFAULT_REFRESH_LEAD default 30-second lead time}.
     */
    public RefreshScheduler() {
        this(DEFAULT_REFRESH_LEAD);
    }

    /**
     * @param refreshLead the lead time before expiry at which a token becomes refresh-eligible; must
     *                    not be {@code null} or negative
     */
    public RefreshScheduler(Duration refreshLead) {
        this.refreshLead = Objects.requireNonNull(refreshLead, "refreshLead must not be null");
        if (refreshLead.isNegative()) {
            throw new IllegalArgumentException("refreshLead must not be negative");
        }
    }

    /**
     * @param token the stored bundle; must not be {@code null}
     * @param now   the reference instant; must not be {@code null}
     * @return whether the access token is at or inside its refresh window at {@code now}; an unknown
     *         expiry ({@link StoredToken#expiresAt()} is {@code null}) is always refresh-eligible
     */
    public boolean needsRefresh(StoredToken token, Instant now) {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(now, "now must not be null");
        Instant expiresAt = token.expiresAt();
        if (expiresAt == null) {
            // Unknown lifetime: with no basis to trust the remaining lifetime, refresh proactively
            // rather than let the token live forever and risk presenting a silently-expired one (L11).
            return true;
        }
        return !now.isBefore(expiresAt.minus(refreshLead));
    }
}
