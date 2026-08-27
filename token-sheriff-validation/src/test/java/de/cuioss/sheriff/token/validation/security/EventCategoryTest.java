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
package de.cuioss.sheriff.token.validation.security;

import de.cuioss.sheriff.token.commons.events.EventCategory;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link EventCategory} enum.
 * 
 * @author Oliver Wolff
 */
@EnableGeneratorController
class EventCategoryTest {

    @Test
    void shouldContainAllExpectedValues() {
        var values = EventCategory.values();
        assertEquals(3, values.length);

        assertArrayEquals(new EventCategory[]{
                EventCategory.INVALID_STRUCTURE,
                EventCategory.INVALID_SIGNATURE,
                EventCategory.SEMANTIC_ISSUES
        }, values);
    }

    @Test
    void shouldProvideValueOfFunctionality() {
        assertEquals(EventCategory.INVALID_STRUCTURE, EventCategory.valueOf("INVALID_STRUCTURE"));
        assertEquals(EventCategory.INVALID_SIGNATURE, EventCategory.valueOf("INVALID_SIGNATURE"));
        assertEquals(EventCategory.SEMANTIC_ISSUES, EventCategory.valueOf("SEMANTIC_ISSUES"));
    }

    @Test
    void shouldThrowExceptionForInvalidValue() {
        assertThrows(IllegalArgumentException.class, () -> EventCategory.valueOf("INVALID_CATEGORY"));
        assertThrows(IllegalArgumentException.class, () -> EventCategory.valueOf(""));
        assertThrows(IllegalArgumentException.class, () -> EventCategory.valueOf("invalid_structure"));
    }

    @Test
    void shouldHandleNullValue() {
        assertThrows(NullPointerException.class, () -> EventCategory.valueOf(null));
    }

    @Test
    void shouldProvideConsistentOrdinalValues() {
        assertEquals(0, EventCategory.INVALID_STRUCTURE.ordinal());
        assertEquals(1, EventCategory.INVALID_SIGNATURE.ordinal());
        assertEquals(2, EventCategory.SEMANTIC_ISSUES.ordinal());
    }

    @Test
    void shouldProvideConsistentStringRepresentation() {
        assertEquals("INVALID_STRUCTURE", EventCategory.INVALID_STRUCTURE.toString());
        assertEquals("INVALID_SIGNATURE", EventCategory.INVALID_SIGNATURE.toString());
        assertEquals("SEMANTIC_ISSUES", EventCategory.SEMANTIC_ISSUES.toString());
    }
}