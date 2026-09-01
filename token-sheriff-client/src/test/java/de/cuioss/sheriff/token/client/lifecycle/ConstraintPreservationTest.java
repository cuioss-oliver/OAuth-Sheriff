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
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sender-constraint preservation across storage and refresh for {@link StoredToken} and
 * {@link TokenLifecycleManager} ({@code CLIENT-18}) — deliverable 9.
 * <p>
 * A DPoP/mTLS-bound token must keep its {@link ConstraintBinding} when stored and when proactively
 * refreshed, so the refreshed token stays bound to the same key.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Sender-constraint preservation across storage + refresh")
class ConstraintPreservationTest {

    @Test
    @DisplayName("Should preserve the DPoP binding when a stored token is stored and read back")
    void shouldPreserveBindingAcrossStorage() {
        var store = new InMemoryTokenStore();
        String sessionId = Generators.letterStrings(10, 20).next();
        ConstraintBinding binding = ConstraintBinding.dpop(Generators.letterStrings(30, 43).next());
        StoredToken token = new StoredToken(Generators.letterStrings(20, 40).next(),
                Generators.letterStrings(20, 40).next(), Generators.letterStrings(20, 40).next(), binding, null,
                null);

        store.store(sessionId, token);
        StoredToken read = store.retrieve(sessionId).orElseThrow();

        assertEquals(binding, read.binding().orElseThrow(), "the stored binding is preserved verbatim");
    }

    @Test
    @DisplayName("Should carry the binding and ID token forward when the manager applies a refresh")
    void shouldPreserveBindingAcrossRefresh() {
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        String sessionId = Generators.letterStrings(10, 20).next();
        ConstraintBinding binding = ConstraintBinding.mtls(Generators.letterStrings(30, 43).next());
        String idToken = Generators.letterStrings(20, 40).next();
        manager.store(sessionId, new StoredToken(Generators.letterStrings(20, 40).next(),
                Generators.letterStrings(20, 40).next(), idToken, binding, Instant.now().plusSeconds(60), null));

        String refreshedAccess = Generators.letterStrings(20, 40).next();
        String refreshedRefresh = Generators.letterStrings(20, 40).next();
        Instant refreshedExpiry = Instant.now().plusSeconds(300);
        StoredToken refreshed = manager.applyRefresh(sessionId, refreshedAccess, refreshedRefresh, refreshedExpiry,
                binding, null)
                .orElseThrow();

        assertAll("refresh preserves constraint",
                () -> assertEquals(refreshedAccess, refreshed.accessToken(), "the access token is rotated"),
                () -> assertEquals(refreshedRefresh, refreshed.refreshToken(), "the refresh token is rotated"),
                () -> assertEquals(binding, refreshed.binding().orElseThrow(),
                        "the binding survives the refresh because the refreshed token re-confirms the same key"),
                () -> assertEquals(idToken, refreshed.idToken(), "the ID token is carried forward"),
                () -> assertEquals(refreshed, manager.get(sessionId).orElseThrow(),
                        "the refreshed bundle replaces the stored one"));
    }

    @Test
    @DisplayName("Should keep the current refresh token when the AS omits a new one on refresh")
    void shouldKeepRefreshTokenWhenNotRotated() {
        String currentRefresh = Generators.letterStrings(20, 40).next();
        ConstraintBinding binding = ConstraintBinding.dpop(Generators.letterStrings(30, 43).next());
        StoredToken token = new StoredToken(Generators.letterStrings(20, 40).next(), currentRefresh, null, binding,
                null, null);

        StoredToken refreshed = token.refreshed(Generators.letterStrings(20, 40).next(), null, null, binding, null);

        assertAll("non-rotating refresh",
                () -> assertEquals(currentRefresh, refreshed.refreshToken(),
                        "the presented refresh token is retained when the AS omits a new one"),
                () -> assertTrue(refreshed.binding().isPresent(), "the binding is still preserved"));
    }
}
