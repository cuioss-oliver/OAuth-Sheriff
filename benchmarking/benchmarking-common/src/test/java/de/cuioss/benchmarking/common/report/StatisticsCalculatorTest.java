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
package de.cuioss.benchmarking.common.report;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for StatisticsCalculator, including EWMA calculations.
 */
class StatisticsCalculatorTest {

    @Test
    void calculateEWMAWithSingleValue() {
        List<Double> values = List.of(50.0);
        double result = StatisticsCalculator.calculateEWMA(values, 0.25);
        assertEquals(50.0, result, 0.001);
    }

    @Test
    void calculateEWMAWithUniformValues() {
        // All values the same should return that value
        List<Double> values = List.of(30.0, 30.0, 30.0, 30.0, 30.0);
        double result = StatisticsCalculator.calculateEWMA(values, 0.25);
        assertEquals(30.0, result, 0.001);
    }

    @Test
    void calculateEWMAWithIncreasingValues() {
        // Recent values weighted more: [50, 40, 30, 20, 10] (newest first)
        // EWMA = (50×1.0 + 40×0.25 + 30×0.0625 + 20×0.015625 + 10×0.00390625) / (1.0 + 0.25 + 0.0625 + 0.015625 + 0.00390625)
        //      = (50 + 10 + 1.875 + 0.3125 + 0.0390625) / 1.33203125
        //      = 62.2265625 / 1.33203125 ≈ 46.7
        List<Double> values = List.of(50.0, 40.0, 30.0, 20.0, 10.0);
        double result = StatisticsCalculator.calculateEWMA(values, 0.25);
        assertTrue(result > 46.0 && result < 48.0, "EWMA should be weighted toward recent higher values");
    }

    @Test
    void calculateEWMAWithRealScenario() {
        // Real scenario: score jumped from 28 to 79
        // History (newest first): [79, 28, 28, 28, 27, 28, 28, 28, 28]
        List<Double> values = List.of(79.0, 28.0, 28.0, 28.0, 27.0, 28.0, 28.0, 28.0, 28.0);

        double result = StatisticsCalculator.calculateEWMA(values, 0.25);

        // Manual calculation:
        // weights: 1.0, 0.25, 0.0625, 0.015625, 0.00390625, ...
        // sum of weights ≈ 1.333...
        // weighted sum ≈ 79×1.0 + 28×0.25 + 28×0.0625 + ... ≈ 79 + 7 + 1.75 + ... ≈ 88
        // EWMA ≈ 88 / 1.333 ≈ 66

        assertTrue(result > 60.0 && result < 70.0,
                "EWMA should be between 60-70 for this dataset, got: " + result);
        assertTrue(result < 79.0, "EWMA should be less than most recent value");
        assertTrue(result > 28.0, "EWMA should be greater than historical values");
    }

    @Test
    void calculateEWMAInvalidLambdaTooSmall() {
        List<Double> values = List.of(50.0);
        assertThrows(IllegalArgumentException.class,
                () -> StatisticsCalculator.calculateEWMA(values, 0.0));
    }

    @Test
    void calculateEWMAInvalidLambdaTooLarge() {
        List<Double> values = List.of(50.0);
        assertThrows(IllegalArgumentException.class,
                () -> StatisticsCalculator.calculateEWMA(values, 1.1));
    }

    @Test
    void calculateEWMANullValues() {
        assertThrows(NullPointerException.class,
                () -> StatisticsCalculator.calculateEWMA(null, 0.25));
    }

    @Test
    void calculateEWMAEmptyList() {
        double result = StatisticsCalculator.calculateEWMA(List.of(), 0.25);
        assertEquals(0.0, result, 0.001);
    }

    @Test
    void calculateEWMADifferentLambdaValues() {
        List<Double> values = List.of(100.0, 50.0, 50.0, 50.0);

        // Smaller lambda = more weight on recent values
        double resultSmallLambda = StatisticsCalculator.calculateEWMA(values, 0.1);
        double resultLargeLambda = StatisticsCalculator.calculateEWMA(values, 0.5);

        // Both should be between 50 and 100
        assertTrue(resultSmallLambda > 50.0 && resultSmallLambda < 100.0);
        assertTrue(resultLargeLambda > 50.0 && resultLargeLambda < 100.0);

        // Smaller lambda gives MORE weight to recent (100), so result should be higher
        assertTrue(resultSmallLambda > resultLargeLambda,
                "Smaller lambda should give more weight to recent value");
    }
}
