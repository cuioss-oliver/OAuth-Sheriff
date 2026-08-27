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

import de.cuioss.sheriff.token.client.token.RefreshTokenFamily;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bounded-growth guard for {@link TokenLifecycleManager#store} family tracking.
 * <p>
 * A session that expires without an explicit logout never reaches
 * {@link TokenLifecycleManager#revokeAndClear}, so its rotation-family entry is not removed on the
 * logout path. Without an eviction policy those entries would leak forever. The manager backs the
 * family map with a size-capped, access-ordered LRU: this test seeds more distinct sessions than the
 * cap and asserts the map stays bounded at the cap and that the least-recently-used (oldest) family
 * is the one evicted.
 */
@EnableTestLogger
@DisplayName("TokenLifecycleManager bounds the refresh-token family map")
class TokenLifecycleManagerFamilyEvictionTest {

    @Test
    @DisplayName("Should evict the least-recently-used family once the cap is exceeded")
    @SuppressWarnings("unchecked")
    void shouldBoundFamilyMapGrowth() throws Exception {
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());

        int cap = readCap();
        int overflow = 5;
        String firstSessionId = "session-0";

        for (int i = 0; i < cap + overflow; i++) {
            // Each stored bundle carries a refresh token, so store() seeds a rotation family per
            // session; distinct session ids therefore drive the map past its cap.
            manager.store("session-" + i, new StoredToken("access-" + i, "refresh-" + i, null, null, null));
        }

        Map<String, RefreshTokenFamily> families = readFamilies(manager);
        synchronized (families) {
            assertEquals(cap, families.size(),
                    "the family map is bounded at the cap even after more sessions were stored");
            assertFalse(families.containsKey(firstSessionId),
                    "the least-recently-used (first-stored) family is evicted once the cap is exceeded");
            assertTrue(families.containsKey("session-" + (cap + overflow - 1)),
                    "the most-recently-stored family is retained");
        }
    }

    private static int readCap() throws ReflectiveOperationException {
        Field capField = TokenLifecycleManager.class.getDeclaredField("MAX_TRACKED_FAMILIES");
        capField.setAccessible(true);
        return capField.getInt(null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, RefreshTokenFamily> readFamilies(TokenLifecycleManager manager)
            throws ReflectiveOperationException {
        Field familiesField = TokenLifecycleManager.class.getDeclaredField("families");
        familiesField.setAccessible(true);
        return (Map<String, RefreshTokenFamily>) familiesField.get(manager);
    }
}
