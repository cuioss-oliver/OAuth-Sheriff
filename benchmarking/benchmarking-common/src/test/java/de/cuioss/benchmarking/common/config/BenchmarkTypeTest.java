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
package de.cuioss.benchmarking.common.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BenchmarkTypeTest {

    @Test
    void microBenchmarkType() {
        BenchmarkType micro = BenchmarkType.MICRO;

        assertEquals("micro", micro.getIdentifier());
        assertEquals("Performance Score", micro.getBadgeLabel());
        assertEquals("Micro Performance", micro.getDisplayName());
        assertEquals("performance-badge.json", micro.getPerformanceBadgeFileName());
        assertEquals("trend-badge.json", micro.getTrendBadgeFileName());
    }

    @Test
    void integrationBenchmarkType() {
        BenchmarkType integration = BenchmarkType.INTEGRATION;

        assertEquals("integration", integration.getIdentifier());
        assertEquals("Integration Performance", integration.getBadgeLabel());
        assertEquals("Integration Performance", integration.getDisplayName());
        assertEquals("integration-performance-badge.json", integration.getPerformanceBadgeFileName());
        assertEquals("integration-trend-badge.json", integration.getTrendBadgeFileName());
    }

    @Test
    void enumValues() {
        BenchmarkType[] values = BenchmarkType.values();
        assertEquals(2, values.length);
        assertEquals(BenchmarkType.MICRO, values[0]);
        assertEquals(BenchmarkType.INTEGRATION, values[1]);
    }

    @Test
    void enumValueOf() {
        assertEquals(BenchmarkType.MICRO, BenchmarkType.valueOf("MICRO"));
        assertEquals(BenchmarkType.INTEGRATION, BenchmarkType.valueOf("INTEGRATION"));

        assertThrows(IllegalArgumentException.class, () -> BenchmarkType.valueOf("INVALID"));
    }

    @Test
    void enumComparison() {
        BenchmarkType micro1 = BenchmarkType.MICRO;
        BenchmarkType micro2 = BenchmarkType.MICRO;
        BenchmarkType integration = BenchmarkType.INTEGRATION;

        assertSame(micro1, micro2);
        assertNotSame(micro1, integration);
        assertEquals(micro1, micro2);
        assertNotEquals(micro1, integration);
    }
}