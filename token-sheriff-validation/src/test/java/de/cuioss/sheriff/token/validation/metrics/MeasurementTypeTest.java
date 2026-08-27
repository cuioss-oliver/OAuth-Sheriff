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
package de.cuioss.sheriff.token.validation.metrics;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link MeasurementType} enum.
 * <p>
 * Verifies that the enum ordinals match the pipeline execution order.
 */
@DisplayName("MeasurementType Tests")
class MeasurementTypeTest {

    @Test
    @DisplayName("Should have ordinals matching description numbers for pipeline steps")
    void shouldHaveOrdinalsMatchingDescriptionNumbers() {
        // Pipeline execution order (0-9)
        assertEquals(0, MeasurementType.COMPLETE_VALIDATION.ordinal());
        assertEquals(1, MeasurementType.TOKEN_PARSING.ordinal());
        assertEquals(2, MeasurementType.ISSUER_EXTRACTION.ordinal());
        assertEquals(3, MeasurementType.CACHE_LOOKUP.ordinal());
        assertEquals(4, MeasurementType.ISSUER_CONFIG_RESOLUTION.ordinal());
        assertEquals(5, MeasurementType.HEADER_VALIDATION.ordinal());
        assertEquals(6, MeasurementType.SIGNATURE_VALIDATION.ordinal());
        assertEquals(7, MeasurementType.TOKEN_BUILDING.ordinal());
        assertEquals(8, MeasurementType.CLAIMS_VALIDATION.ordinal());
        assertEquals(9, MeasurementType.CACHE_STORE.ordinal());
    }

    @Test
    @DisplayName("Should have descriptions starting with ordinal number")
    void shouldHaveDescriptionsStartingWithOrdinalNumber() {
        assertTrue(MeasurementType.COMPLETE_VALIDATION.getDescription().startsWith("0."));
        assertTrue(MeasurementType.TOKEN_PARSING.getDescription().startsWith("1."));
        assertTrue(MeasurementType.ISSUER_EXTRACTION.getDescription().startsWith("2."));
        assertTrue(MeasurementType.CACHE_LOOKUP.getDescription().startsWith("3."));
        assertTrue(MeasurementType.ISSUER_CONFIG_RESOLUTION.getDescription().startsWith("4."));
        assertTrue(MeasurementType.HEADER_VALIDATION.getDescription().startsWith("5."));
        assertTrue(MeasurementType.SIGNATURE_VALIDATION.getDescription().startsWith("6."));
        assertTrue(MeasurementType.TOKEN_BUILDING.getDescription().startsWith("7."));
        assertTrue(MeasurementType.CLAIMS_VALIDATION.getDescription().startsWith("8."));
        assertTrue(MeasurementType.CACHE_STORE.getDescription().startsWith("9."));
    }

    @Test
    @DisplayName("Should have all 10 enum values")
    void shouldHaveAll15EnumValues() {
        assertEquals(10, MeasurementType.values().length);
    }

    @Test
    @DisplayName("Pipeline execution sequence should be in correct order")
    void pipelineExecutionSequenceShouldBeInCorrectOrder() {
        // Verify the natural enum ordering matches pipeline execution
        MeasurementType[] values = MeasurementType.values();

        // Main pipeline flow for access tokens (0-9)
        assertSame(MeasurementType.COMPLETE_VALIDATION, values[0]);
        assertSame(MeasurementType.TOKEN_PARSING, values[1]);
        assertSame(MeasurementType.ISSUER_EXTRACTION, values[2]);
        assertSame(MeasurementType.CACHE_LOOKUP, values[3]); // Early, before expensive signature
        assertSame(MeasurementType.ISSUER_CONFIG_RESOLUTION, values[4]);
        assertSame(MeasurementType.HEADER_VALIDATION, values[5]);
        assertSame(MeasurementType.SIGNATURE_VALIDATION, values[6]); // Most expensive
        assertSame(MeasurementType.TOKEN_BUILDING, values[7]);
        assertSame(MeasurementType.CLAIMS_VALIDATION, values[8]);
        assertSame(MeasurementType.CACHE_STORE, values[9]);
    }

    @Test
    @DisplayName("Should verify cache lookup happens before signature validation")
    void shouldVerifyCacheLookupHappensBeforeSignatureValidation() {
        // This is the key optimization from issue #131
        assertTrue(MeasurementType.CACHE_LOOKUP.ordinal() < MeasurementType.SIGNATURE_VALIDATION.ordinal(),
                "Cache lookup should happen before expensive signature validation");
    }
}
