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

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.UnaryOperator;

/**
 * The default in-memory {@link TokenStore} — a thread-safe, single-instance store keyed by session id.
 * <p>
 * Backed by a {@link ConcurrentHashMap}, so per-session {@code store} / {@code retrieve} /
 * {@code remove} are individually atomic and there is no cross-session interference
 * ({@code CLIENT-22}). It suits a single application instance; a horizontally-scaled BFF that needs a
 * shared, persistent store provides its own {@link TokenStore} implementation instead.
 * <p>
 * Tokens live only in process memory and are removed on logout; nothing is written to disk here.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class InMemoryTokenStore implements TokenStore {

    private final ConcurrentMap<String, StoredToken> tokens = new ConcurrentHashMap<>();

    @Override
    public void store(String sessionId, StoredToken token) {
        tokens.put(requireSessionId(sessionId), Objects.requireNonNull(token, "token must not be null"));
    }

    @Override
    public Optional<StoredToken> retrieve(String sessionId) {
        return Optional.ofNullable(tokens.get(requireSessionId(sessionId)));
    }

    @Override
    public Optional<StoredToken> remove(String sessionId) {
        return Optional.ofNullable(tokens.remove(requireSessionId(sessionId)));
    }

    @Override
    public Optional<StoredToken> update(String sessionId, UnaryOperator<StoredToken> updater) {
        Objects.requireNonNull(updater, "updater must not be null");
        // computeIfPresent performs the read-modify-write atomically per key, so a concurrent remove
        // (logout) cannot interleave between the read and the write and resurrect a revoked session.
        return Optional.ofNullable(
                tokens.computeIfPresent(requireSessionId(sessionId), (key, current) -> updater.apply(current)));
    }

    private static String requireSessionId(String sessionId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        if (sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId must not be blank");
        }
        return sessionId;
    }
}
