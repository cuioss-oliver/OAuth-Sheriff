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

import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Service-provider interface for the server-side token store ({@code CLIENT-19}, design fork 2).
 * <p>
 * The engine keeps retrieved tokens server-side, off the browser, keyed by an opaque session
 * identifier. It does not force the stateful-vs-stateless choice on the relying party: the default
 * {@link InMemoryTokenStore} suffices for a single instance, while a BFF that needs a persistent,
 * shared store (Redis, a database, an encrypted cache) plugs its own implementation without changing
 * the engine.
 * <p>
 * Implementations MUST be thread-safe — concurrent flows for different sessions, and concurrent
 * refresh/logout for the same session, operate on the store simultaneously ({@code CLIENT-22}).
 * {@link #remove(String)} MUST be atomic: it returns the removed bundle so a logout can take-and-clear
 * a session's tokens in one step, with no window in which another flow observes a token that is being
 * revoked.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public interface TokenStore {

    /**
     * Stores (or replaces) the token bundle for a session.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @param token     the token bundle to store; must not be {@code null}
     */
    void store(String sessionId, StoredToken token);

    /**
     * Retrieves the token bundle held for a session.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @return the stored bundle, or {@link Optional#empty()} when none is held
     */
    Optional<StoredToken> retrieve(String sessionId);

    /**
     * Atomically removes and returns the token bundle held for a session.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @return the removed bundle, or {@link Optional#empty()} when none was held
     */
    Optional<StoredToken> remove(String sessionId);

    /**
     * Atomically applies {@code updater} to the token bundle held for a session, storing the result.
     * <p>
     * The retrieve-transform-store cycle happens as a single atomic operation with respect to
     * concurrent {@link #store(String, StoredToken)} / {@link #remove(String)} / {@code update} calls
     * for the same session, closing the read-modify-write race a naive
     * {@code retrieve} → transform → {@code store} sequence leaves open: a concurrent
     * {@link #remove(String)} (logout) between the read and the write could otherwise resurrect a
     * just-revoked session by writing a refreshed token back into it, violating the
     * no-stale-read-after-logout guarantee ({@code CLIENT-22}). When no bundle is held the updater is
     * never invoked and the store is left untouched.
     *
     * @param sessionId the opaque session identifier; must not be {@code null} or blank
     * @param updater   the transform applied to the currently-held bundle to produce its successor;
     *                  must not be {@code null} and must not return {@code null}
     * @return the updated (stored) bundle, or {@link Optional#empty()} when no bundle was held
     */
    Optional<StoredToken> update(String sessionId, UnaryOperator<StoredToken> updater);
}
