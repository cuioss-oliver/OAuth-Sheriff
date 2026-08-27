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
package de.cuioss.sheriff.token.validation.benchmark;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import de.cuioss.sheriff.token.validation.metrics.MeasurementType;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

class LibraryMetricsExporterTest {

    private final Gson gson = new GsonBuilder().create();

    @Test
    void shouldExportMetricsToJsonFile() throws Exception {
        // Given
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.builder()
                .measurementType(MeasurementType.TOKEN_PARSING)
                .measurementType(MeasurementType.HEADER_VALIDATION)
                .build()
                .createMonitor();

        // Simulate some measurements with actual time delay
        long parseStart = System.nanoTime();

        // Wait a bit to simulate parsing time
        await()
                .atMost(50, TimeUnit.MILLISECONDS)
                .pollDelay(10, TimeUnit.MILLISECONDS)
                .until(() -> true);

        long parseDuration = System.nanoTime() - parseStart;
        monitor.recordMeasurement(MeasurementType.TOKEN_PARSING, parseDuration);

        long headerStart = System.nanoTime();

        // Wait a bit to simulate header validation time
        await()
                .atMost(20, TimeUnit.MILLISECONDS)
                .pollDelay(5, TimeUnit.MILLISECONDS)
                .until(() -> true);

        long headerDuration = System.nanoTime() - headerStart;
        monitor.recordMeasurement(MeasurementType.HEADER_VALIDATION, headerDuration);

        // When
        LibraryMetricsExporter.exportMetrics("test-benchmark", monitor);

        // Then - metrics are exported to hardcoded target/benchmark-results
        Path resultsDir = Path.of("target/benchmark-results");
        Path[] jsonFiles = Files.list(resultsDir)
                .filter(p -> p.toString().endsWith(".json"))
                .toArray(Path[]::new);

        assertEquals(1, jsonFiles.length);
        assertEquals("jwt-validation-metrics.json", jsonFiles[0].getFileName().toString());

        String jsonContent = Files.readString(jsonFiles[0]);
        TypeToken<Map<String, Object>> typeToken = new TypeToken<>() {
        };
        Map<String, Object> allMetrics = gson.fromJson(jsonContent, typeToken.getType());

        // Verify we have at least one benchmark entry (unknown_benchmark since no specific benchmark name is set)
        assertFalse(allMetrics.isEmpty());

        // Get the first benchmark entry (should be "unknown_benchmark")
        String benchmarkName = allMetrics.keySet().iterator().next();
        @SuppressWarnings("unchecked") Map<String, Object> benchmarkMetrics = (Map<String, Object>) allMetrics.get(benchmarkName);

        // Verify JSON structure for the benchmark
        assertNotNull(benchmarkMetrics.get("timestamp"));
        assertNotNull(benchmarkMetrics.get("steps"));

        @SuppressWarnings("unchecked") Map<String, Map<String, Object>> steps = (Map<String, Map<String, Object>>) benchmarkMetrics.get("steps");
        assertTrue(steps.containsKey("token_parsing"));
        assertTrue(steps.containsKey("header_validation"));

        // Verify metrics exist
        Map<String, Object> parseMetrics = steps.get("token_parsing");
        assertNotNull(parseMetrics.get("sample_count"));
        assertNotNull(parseMetrics.get("p50_us"));
        assertNotNull(parseMetrics.get("p95_us"));
        assertNotNull(parseMetrics.get("p99_us"));
    }

    @Test
    void shouldFormatNumbersCorrectly() throws Exception {
        // Given
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.builder()
                .measurementType(MeasurementType.TOKEN_PARSING)
                .measurementType(MeasurementType.SIGNATURE_VALIDATION)
                .build()
                .createMonitor();

        // Simulate measurements with values that would result in < 10 and >= 10 microseconds
        // Small measurement < 10 microseconds (e.g., 7.6)
        monitor.recordMeasurement(MeasurementType.TOKEN_PARSING, 7600); // 7.6 microseconds

        // Large measurement >= 10 microseconds (e.g., 13)
        monitor.recordMeasurement(MeasurementType.SIGNATURE_VALIDATION, 13000); // 13 microseconds

        // When
        LibraryMetricsExporter.exportMetrics("test-benchmark", monitor);

        // Then - metrics are exported to hardcoded target/benchmark-results
        Path jsonFile = Path.of("target/benchmark-results/jwt-validation-metrics.json");
        String jsonContent = Files.readString(jsonFile);

        // Verify that values < 10 have one decimal place
        assertTrue(jsonContent.contains("7.6"), "Values < 10 should have one decimal place");

        // Verify that values >= 10 are integers without decimal point
        assertTrue(jsonContent.contains("\"p50_us\": 13"), "Values >= 10 should be integers without decimal");
    }
}
