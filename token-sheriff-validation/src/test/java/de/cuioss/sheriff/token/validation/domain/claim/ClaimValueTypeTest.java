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
package de.cuioss.sheriff.token.validation.domain.claim;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests ClaimValueType functionality")
class ClaimValueTypeTest {

    @Test
    @DisplayName("Should have all expected enum values")
    void shouldHaveAllExpectedValues() {
        // Given, When, Then
        assertEquals(3, ClaimValueType.values().length);

        assertNotNull(ClaimValueType.STRING, "STRING enum value should not be null");
        assertNotNull(ClaimValueType.STRING_LIST, "STRING_LIST enum value should not be null");
        assertNotNull(ClaimValueType.DATETIME, "DATETIME enum value should not be null");
    }

    @Test
    @DisplayName("Should convert enum values to string correctly")
    void shouldConvertToStringCorrectly() {
        // Given, When, Then
        assertEquals("STRING", ClaimValueType.STRING.toString());
        assertEquals("STRING_LIST", ClaimValueType.STRING_LIST.toString());
        assertEquals("DATETIME", ClaimValueType.DATETIME.toString());
    }

    @Test
    @DisplayName("Should be able to get enum value by name")
    void shouldGetEnumValueByName() {
        // Given, When, Then
        assertEquals(ClaimValueType.STRING, ClaimValueType.valueOf("STRING"));
        assertEquals(ClaimValueType.STRING_LIST, ClaimValueType.valueOf("STRING_LIST"));
        assertEquals(ClaimValueType.DATETIME, ClaimValueType.valueOf("DATETIME"));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException for invalid enum name")
    void shouldThrowExceptionForInvalidName() {
        // Given, When, Then
        assertThrows(IllegalArgumentException.class, () ->
                ClaimValueType.valueOf("INVALID_TYPE"));
    }
}