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
package de.cuioss.benchmarking.common.metrics;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for {@link BenchmarkMetricsTransformer}, focusing on correct handling of
 * metrics backed by multiple series (multi-label metrics).
 */
class BenchmarkMetricsTransformerTest {

    private static final Instant START = Instant.ofEpochSecond(1758792520);
    private static final Instant END = Instant.ofEpochSecond(1758792760);

    private final BenchmarkMetricsTransformer transformer = new BenchmarkMetricsTransformer();

    private static PrometheusClient.TimeSeries series(String metric, Map<String, String> labels, double... values) {
        List<PrometheusClient.DataPoint> points = new ArrayList<>();
        long ts = START.getEpochSecond();
        for (double value : values) {
            points.add(new PrometheusClient.DataPoint(Instant.ofEpochSecond(ts), value));
            ts += 2;
        }
        return new PrometheusClient.TimeSeries(metric, labels, points);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldSelectHeapSeriesFromMultiSeriesMemoryMetric() {
        // Given - nonheap series FIRST, heap series second: the transformer must select
        // by the area label, not simply take the first series
        double heapBytes = 512.0 * 1024 * 1024;
        Map<String, List<PrometheusClient.TimeSeries>> data = Map.of(
                "jvm_memory_used_bytes", List.of(
                        series("jvm_memory_used_bytes", Map.of("area", "nonheap", "id", "code cache"),
                                42.0 * 1024 * 1024, 42.0 * 1024 * 1024),
                        series("jvm_memory_used_bytes", Map.of("area", "heap", "id", "eden space"),
                                heapBytes, heapBytes)));

        // When
        Map<String, Object> result = transformer.transformToServerMetrics("test", START, END, data);

        // Then
        Map<String, Object> resources = (Map<String, Object>) result.get("resources");
        Map<String, Object> memory = (Map<String, Object>) resources.get("memory");
        Map<String, Object> heap = (Map<String, Object>) memory.get("heap");

        assertEquals(512.0, heap.get("average_mb"), "Heap metrics must come from the area=heap series");
        assertEquals(512.0, heap.get("peak_mb"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldAggregateJwtValidationsAcrossAllSeries() {
        // Given - success counter split across two series with different event_type labels
        Map<String, List<PrometheusClient.TimeSeries>> data = Map.of(
                "sheriff_token_validation_success_operations_total", List.of(
                        series("sheriff_token_validation_success_operations_total",
                                Map.of("event_type", "ACCESS_TOKEN_CREATED"), 100.0, 300.0),
                        series("sheriff_token_validation_success_operations_total",
                                Map.of("event_type", "ACCESS_TOKEN_CACHE_HIT"), 50.0, 150.0)));

        // When
        Map<String, Object> result = transformer.transformToServerMetrics("test", START, END, data);

        // Then - deltas of ALL series are summed: (300-100) + (150-50) = 300
        Map<String, Object> application = (Map<String, Object>) result.get("application");
        Map<String, Object> jwtValidations = (Map<String, Object>) application.get("jwt_validations");

        assertEquals(300, jwtValidations.get("success"));
        assertEquals(100, jwtValidations.get("cache_hits"), "Cache hits come from the CACHE_HIT series only");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldHandleMissingMetricsGracefully() {
        Map<String, Object> result = transformer.transformToServerMetrics("test", START, END, Map.of());

        Map<String, Object> resources = (Map<String, Object>) result.get("resources");
        Map<String, Object> memory = (Map<String, Object>) resources.get("memory");
        Map<String, Object> heap = (Map<String, Object>) memory.get("heap");

        assertEquals(0.0, heap.get("average_mb"));
        assertNotNull(result.get("application"));
    }
}
