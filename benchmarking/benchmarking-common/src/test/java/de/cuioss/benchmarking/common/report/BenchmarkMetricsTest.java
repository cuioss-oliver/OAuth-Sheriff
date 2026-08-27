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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BenchmarkMetrics} validation.
 */
class BenchmarkMetricsTest {

    @Test
    void shouldAcceptPositiveValues() {
        BenchmarkMetrics metrics = new BenchmarkMetrics("thrpt", "lat", 1000.0, 1.5, 55, "C");
        assertEquals(1000.0, metrics.throughput());
        assertEquals(1.5, metrics.latency());
    }

    @Test
    void shouldAcceptZeroThroughputAndLatencyForDegradedRuns() {
        // Failed/empty runs must produce an F-grade report instead of crashing
        BenchmarkMetrics metrics = assertDoesNotThrow(
                () -> new BenchmarkMetrics("N/A", "N/A", 0.0, 0.0, 0, "F"));
        assertEquals("F", metrics.performanceGrade());
        assertEquals(0.0, metrics.throughput());
        assertEquals(0.0, metrics.latency());
    }

    @Test
    void shouldRejectNegativeValues() {
        assertThrows(IllegalArgumentException.class,
                () -> new BenchmarkMetrics("a", "b", -1.0, 1.0, 0, "F"));
        assertThrows(IllegalArgumentException.class,
                () -> new BenchmarkMetrics("a", "b", 1.0, -1.0, 0, "F"));
        assertThrows(IllegalArgumentException.class,
                () -> new BenchmarkMetrics("a", "b", 1.0, 1.0, -1, "F"));
    }

    @Test
    void shouldRejectMissingNames() {
        assertThrows(IllegalArgumentException.class,
                () -> new BenchmarkMetrics(null, "b", 1.0, 1.0, 0, "F"));
        assertThrows(IllegalArgumentException.class,
                () -> new BenchmarkMetrics("a", " ", 1.0, 1.0, 0, "F"));
    }
}
