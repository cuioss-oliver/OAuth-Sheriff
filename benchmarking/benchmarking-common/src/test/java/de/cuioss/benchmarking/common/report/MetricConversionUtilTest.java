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

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Metrics.Units.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetricConversionUtilTest {

    private static final double DELTA = 0.0001;

    @Test
    void convertToMillisecondsPerOpFromMicroseconds() {
        // Test case from actual data: 802.9 us/op should convert to 0.8029 ms/op
        double score = 802.9010071674597;
        String unit = US_PER_OP;

        double result = MetricConversionUtil.convertToMillisecondsPerOp(score, unit);

        assertEquals(0.8029010071674597, result, DELTA,
                "802.9 us/op should convert to 0.8029 ms/op");
    }

    @Test
    void convertToMillisecondsPerOpFromOpsPerSecond() {
        // Test case from actual data: 103380.87 ops/s should convert to ~0.00967 ms/op
        double score = 103380.86760034731;
        String unit = OPS_PER_SEC;

        double result = MetricConversionUtil.convertToMillisecondsPerOp(score, unit);

        assertEquals(0.009673, result, DELTA,
                "103380.87 ops/s should convert to ~0.00967 ms/op");
    }

    @Test
    void convertToMillisecondsPerOpAllUnits() {
        // Test all supported units
        
        // Latency units
        assertEquals(100.0, MetricConversionUtil.convertToMillisecondsPerOp(100.0, MS_PER_OP),
                "ms/op should return unchanged");
        assertEquals(1000.0, MetricConversionUtil.convertToMillisecondsPerOp(1.0, SEC_PER_OP),
                "1 s/op = 1000 ms/op");
        assertEquals(0.001, MetricConversionUtil.convertToMillisecondsPerOp(1.0, US_PER_OP), DELTA,
                "1 us/op = 0.001 ms/op");
        assertEquals(0.000001, MetricConversionUtil.convertToMillisecondsPerOp(1.0, NS_PER_OP), DELTA,
                "1 ns/op = 0.000001 ms/op");

        // Throughput units (need inversion)
        assertEquals(1.0, MetricConversionUtil.convertToMillisecondsPerOp(1000.0, OPS_PER_SEC), DELTA,
                "1000 ops/s = 1 ms/op");
        assertEquals(1.0, MetricConversionUtil.convertToMillisecondsPerOp(1.0, OPS_PER_MS), DELTA,
                "1 ops/ms = 1 ms/op");
        assertEquals(1.0, MetricConversionUtil.convertToMillisecondsPerOp(0.001, OPS_PER_US), DELTA,
                "0.001 ops/us = 1 ms/op");
        assertEquals(1.0, MetricConversionUtil.convertToMillisecondsPerOp(0.000001, OPS_PER_NS), DELTA,
                "0.000001 ops/ns = 1 ms/op");
    }

    @Test
    void convertToOpsPerSecondAllUnits() {
        // Throughput units
        assertEquals(1000.0, MetricConversionUtil.convertToOpsPerSecond(1000.0, OPS_PER_SEC),
                "ops/s should return unchanged");
        assertEquals(1000.0, MetricConversionUtil.convertToOpsPerSecond(1.0, OPS_PER_MS),
                "1 ops/ms = 1000 ops/s");
        assertEquals(1000000.0, MetricConversionUtil.convertToOpsPerSecond(1.0, OPS_PER_US),
                "1 ops/us = 1000000 ops/s");

        // Latency units (need inversion)
        assertEquals(1000.0, MetricConversionUtil.convertToOpsPerSecond(1.0, MS_PER_OP), DELTA,
                "1 ms/op = 1000 ops/s");
        assertEquals(1.0, MetricConversionUtil.convertToOpsPerSecond(1.0, SEC_PER_OP), DELTA,
                "1 s/op = 1 ops/s");
    }

    @Test
    void realWorldScenarioMixedUnits() {
        // Test with actual benchmark data
        double[] scores = {
                103380.86760034731,  // ops/s
                123186.37644751598,  // ops/s
                190655.18461176465,  // ops/s
                802.9010071674597,   // us/op
                927.2665043930523    // us/op
        };
        String[] units = {
                OPS_PER_SEC, OPS_PER_SEC, OPS_PER_SEC, US_PER_OP, US_PER_OP
        };

        double totalLatencyMs = 0;
        int count = 0;

        for (int i = 0; i < scores.length; i++) {
            double latencyMs = MetricConversionUtil.convertToMillisecondsPerOp(scores[i], units[i]);
            assertTrue(latencyMs > 0, "Conversion should produce positive value");
            totalLatencyMs += latencyMs;
            count++;
        }

        double averageLatencyMs = totalLatencyMs / count;

        // Average should be around 0.35 ms (definitely not 346 seconds!)
        assertTrue(averageLatencyMs < 0.4,
                "Average latency should be less than 0.4 ms, got: " + averageLatencyMs);
        assertTrue(averageLatencyMs > 0.3,
                "Average latency should be more than 0.3 ms, got: " + averageLatencyMs);
    }

    @Test
    void unknownUnit() {
        // Unknown unit should return 0 for filtering
        assertEquals(0, MetricConversionUtil.convertToMillisecondsPerOp(100, "unknown"),
                "Unknown unit should return 0");
    }

    @Test
    void formatForDisplayWithDifferentValues() {
        // Values < 2: 2 fraction digits
        assertEquals("0.50", MetricConversionUtil.formatForDisplay(0.5));
        assertEquals("1.25", MetricConversionUtil.formatForDisplay(1.25));
        assertEquals("1.99", MetricConversionUtil.formatForDisplay(1.99));

        // Values < 10: 1 fraction digit
        assertEquals("2.0", MetricConversionUtil.formatForDisplay(2.0));
        assertEquals("5.5", MetricConversionUtil.formatForDisplay(5.5));
        assertEquals("9.9", MetricConversionUtil.formatForDisplay(9.9));

        // Values >= 10: No fraction digits
        assertEquals("10", MetricConversionUtil.formatForDisplay(10.0));
        assertEquals("84", MetricConversionUtil.formatForDisplay(83.9));
        assertEquals("103", MetricConversionUtil.formatForDisplay(103.4));
        assertEquals("1000", MetricConversionUtil.formatForDisplay(1000.0));
        assertEquals("123457", MetricConversionUtil.formatForDisplay(123456.789));
    }

    @Test
    void formatForDisplayEdgeCases() {
        // Test exact boundaries
        assertEquals("2.0", MetricConversionUtil.formatForDisplay(2.0));
        assertEquals("10", MetricConversionUtil.formatForDisplay(10.0));

        // Test very small values
        assertEquals("0.01", MetricConversionUtil.formatForDisplay(0.01));
        assertEquals("0.12", MetricConversionUtil.formatForDisplay(0.123));

        // Test rounding
        assertEquals("9.5", MetricConversionUtil.formatForDisplay(9.49));
        assertEquals("9.5", MetricConversionUtil.formatForDisplay(9.51));
        assertEquals("100", MetricConversionUtil.formatForDisplay(99.5));
        assertEquals("100", MetricConversionUtil.formatForDisplay(100.4));
    }
}