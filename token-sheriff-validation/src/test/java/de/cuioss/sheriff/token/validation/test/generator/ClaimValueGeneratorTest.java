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
package de.cuioss.sheriff.token.validation.test.generator;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValueType;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ClaimValueGenerator}.
 */
@EnableGeneratorController
@DisplayName("Tests ClaimValueGenerator functionality")
class ClaimValueGeneratorTest {

    @Test
    @DisplayName("Default generator should create non-null ClaimValue objects")
    void defaultGeneratorShouldCreateNonNullClaimValues() {
        // Given a default generator
        var generator = new ClaimValueGenerator();

        // When generating multiple claim values
        int count = 100;
        Set<ClaimValueType> observedTypes = new HashSet<>();

        for (int i = 0; i < count; i++) {
            ClaimValue claimValue = generator.next();

            // Then each claim value should be non-null
            assertNotNull(claimValue, "Generated ClaimValue should not be null");

            // And original string should not be null
            assertNotNull(claimValue.getOriginalString(), "Original string should not be null");

            // Track observed types
            observedTypes.add(claimValue.getType());
        }

        // We should have observed all types (with high probability)
        assertEquals(ClaimValueType.values().length, observedTypes.size(),
                "Should have observed all claim value types");
    }

    @Test
    @DisplayName("Generator with allowNullOriginalString should sometimes create ClaimValues with null original strings")
    void generatorWithAllowNullOriginalStringShouldSometimesCreateClaimValuesWithNullOriginalStrings() {
        // Given a generator that allows null original strings
        var generator = new ClaimValueGenerator(true);

        // When generating many claim values
        int count = 100;
        boolean foundNullOriginalString = false;

        for (int i = 0; i < count; i++) {
            ClaimValue claimValue = generator.next();

            // Then some claim values should have null original strings
            if (claimValue.getOriginalString() == null) {
                foundNullOriginalString = true;
                break;
            }
        }

        assertTrue(foundNullOriginalString, "Should have found at least one ClaimValue with null original string");
    }

    @Test
    @DisplayName("Generator with fixed type should only create ClaimValues of that type")
    void generatorWithFixedTypeShouldOnlyCreateClaimValuesOfThatType() {
        // For each claim value type
        for (ClaimValueType fixedType : ClaimValueType.values()) {
            // Given a generator with that fixed type
            var generator = new ClaimValueGenerator(fixedType);

            // When generating multiple claim values
            int count = 10;

            for (int i = 0; i < count; i++) {
                ClaimValue claimValue = generator.next();

                // Then each claim value should be of the fixed type
                assertEquals(fixedType, claimValue.getType(),
                        "Generated ClaimValue should be of type " + fixedType);

                // And should have appropriate properties based on type
                switch (fixedType) {
                    case STRING:
                        // For STRING type, asList should be empty and dateTime should be null
                        assertTrue(claimValue.getAsList().isEmpty(), "asList should be empty for STRING type");
                        assertNull(claimValue.getDateTime(), "dateTime should be null for STRING type");
                        break;
                    case STRING_LIST:
                        // For STRING_LIST type, asList should not be null and dateTime should be null
                        assertNotNull(claimValue.getAsList(), "asList should not be null for STRING_LIST type");
                        assertNull(claimValue.getDateTime(), "dateTime should be null for STRING_LIST type");
                        break;
                    case DATETIME:
                        // For DATETIME type, asList should be empty and dateTime should not be null
                        assertTrue(claimValue.getAsList().isEmpty(), "asList should be empty for DATETIME type");
                        assertNotNull(claimValue.getDateTime(), "dateTime should not be null for DATETIME type");
                        break;
                }
            }
        }
    }

    @Test
    @DisplayName("Generator should create diverse ClaimValues")
    void generatorShouldCreateDiverseClaimValues() {
        // Given a default generator
        var generator = new ClaimValueGenerator();

        // When generating many claim values
        int count = 100;
        Set<String> uniqueOriginalStrings = new HashSet<>();
        Set<OffsetDateTime> uniqueDateTimes = new HashSet<>();
        int nonEmptyListCount = 0;

        for (int i = 0; i < count; i++) {
            ClaimValue claimValue = generator.next();

            // Track unique values
            if (claimValue.getOriginalString() != null) {
                uniqueOriginalStrings.add(claimValue.getOriginalString());
            }

            if (claimValue.getDateTime() != null) {
                uniqueDateTimes.add(claimValue.getDateTime());
            }

            if (!claimValue.getAsList().isEmpty()) {
                nonEmptyListCount++;
            }
        }

        // Then we should have observed diverse values
        assertTrue(uniqueOriginalStrings.size() > 1, "Should have generated multiple unique original strings");

        if (!uniqueDateTimes.isEmpty()) {
            assertTrue(uniqueDateTimes.size() > 1, "Should have generated multiple unique date times");
        }

        if (nonEmptyListCount > 0) {
            assertTrue(nonEmptyListCount > 1, "Should have generated multiple non-empty lists");
        }
    }
}