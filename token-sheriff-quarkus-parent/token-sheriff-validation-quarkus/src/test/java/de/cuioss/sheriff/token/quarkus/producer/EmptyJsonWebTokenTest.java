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
package de.cuioss.sheriff.token.quarkus.producer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link EmptyJsonWebToken}.
 *
 * @author Oliver Wolff
 */
@DisplayName("EmptyJsonWebToken")
class EmptyJsonWebTokenTest {

    private final EmptyJsonWebToken underTest = EmptyJsonWebToken.INSTANCE;

    @Test
    @DisplayName("getName should return null")
    void getNameShouldReturnNull() {
        assertNull(underTest.getName());
    }

    @Test
    @DisplayName("getClaimNames should return empty set")
    void getClaimNamesShouldReturnEmptySet() {
        var claimNames = underTest.getClaimNames();
        assertNotNull(claimNames);
        assertTrue(claimNames.isEmpty());
    }

    @Test
    @DisplayName("getClaim should return null for any claim name")
    void getClaimShouldReturnNull() {
        assertNull(underTest.getClaim("sub"));
        assertNull(underTest.getClaim("iss"));
        assertNull(underTest.getClaim("exp"));
        assertNull(underTest.getClaim("nonexistent"));
    }

    @Test
    @DisplayName("INSTANCE should be a singleton")
    void instanceShouldBeSingleton() {
        assertSame(EmptyJsonWebToken.INSTANCE, underTest);
    }
}
