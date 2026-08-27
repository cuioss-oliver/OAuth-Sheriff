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
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests CollectionClaimHandler functionality")
class CollectionClaimHandlerTest {

    private static final String TEST_STRING = "test-value";
    private static final List<String> TEST_VALUES = List.of("value1", "value2", "value3");
    private static final CuiLogger LOGGER = new CuiLogger(CollectionClaimHandlerTest.class);

    @Test
    @DisplayName("Provides values matching expected values")
    void shouldProvideExpectedValues() {
        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        assertTrue(handler.providesValues(TEST_VALUES), "Should provide all expected values");
        assertTrue(handler.determineMissingValues(TEST_VALUES).isEmpty(), "No values should be missing");
    }

    @Test
    @DisplayName("Check if claim provides all expected values")
    void shouldCheckIfClaimProvidesAllExpectedValues() {
        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        assertTrue(handler.providesValues(List.of("value1")),
                "Should return true when claim provides the expected value");
        assertTrue(handler.providesValues(List.of("value1", "value2")),
                "Should return true when claim provides all expected values");
        assertFalse(handler.providesValues(List.of("value1", "value4")),
                "Should return false when claim does not provide all expected values");
    }

    @Test
    @DisplayName("Handle empty expected values")
    void shouldHandleEmptyExpectedValues() {
        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        assertTrue(handler.providesValues(List.of()),
                "Should return true when expected values is empty");
    }

    @Test
    @DisplayName("Reject null expected values")
    void shouldRejectNullExpectedValues() {
        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        assertThrows(NullPointerException.class, () -> handler.providesValues(null),
                "Should throw NullPointerException when expected values is null");
    }

    @Test
    @DisplayName("Should determine missing values")
    void shouldDetermineMissingValues() {

        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        // When, Then
        assertTrue(handler.determineMissingValues(List.of("value1")).isEmpty(),
                "Should return empty set when all expected values are present");

        Set<String> missingValues = handler.determineMissingValues(List.of("value1", "value4", "value5"));
        assertEquals(2, missingValues.size(), "Should return set with 2 missing values");
        assertTrue(missingValues.contains("value4"), "Missing values should contain 'value4'");
        assertTrue(missingValues.contains("value5"), "Missing values should contain 'value5'");
    }

    @Test
    @DisplayName("Should check if claim provides values and log debug info")
    void shouldCheckIfClaimProvidesValuesAndLogDebugInfo() {

        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, TEST_VALUES);
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);
        String logContext = "test-context";

        // When, Then
        assertTrue(handler.providesValuesAndDebugIfValuesMissing(
                        List.of("value1"), logContext, LOGGER),
                "Should return true when all expected values are present");

        assertFalse(handler.providesValuesAndDebugIfValuesMissing(
                        List.of("value1", "value4"), logContext, LOGGER),
                "Should return false when not all expected values are present");
    }

    @Test
    @DisplayName("Should handle empty claim values")
    void shouldHandleEmptyClaimValues() {

        ClaimValue claimValue = ClaimValue.forList(TEST_STRING, List.of());
        CollectionClaimHandler handler = new CollectionClaimHandler(claimValue);

        // When, Then
        assertTrue(handler.providesValues(List.of()), "Should provide empty values");
        assertTrue(handler.providesValues(List.of()),
                "Should return true for empty expected values");
        assertFalse(handler.providesValues(List.of("value1")),
                "Should return false when claim has no values but expected values are not empty");

        Set<String> missingValues = handler.determineMissingValues(List.of("value1"));
        assertEquals(1, missingValues.size(), "Should return set with 1 missing value");
        assertTrue(missingValues.contains("value1"), "Missing values should contain 'value1'");
    }
}