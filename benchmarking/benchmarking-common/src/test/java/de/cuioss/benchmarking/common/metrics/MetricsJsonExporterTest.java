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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for MetricsJsonExporter
 */
class MetricsJsonExporterTest {

    @TempDir
    Path tempDir;

    private Path targetDir;
    private MetricsJsonExporter exporter;
    private Gson gson = new Gson();

    @BeforeEach
    void setUp() {
        targetDir = tempDir.resolve("target");
        exporter = new MetricsJsonExporter(targetDir);
    }

    @Test
    void shouldCreateTargetDirectoryOnInitialization() {
        Path newTargetDir = tempDir.resolve("new-target");
        assertFalse(Files.exists(newTargetDir), "Directory should not exist initially");

        new MetricsJsonExporter(newTargetDir);

        assertTrue(Files.exists(newTargetDir), "Directory should be created during initialization");
    }

    @Test
    void shouldExportToFileSuccessfully() throws Exception {
        Map<String, Object> testData = new HashMap<>();
        testData.put("test_key", "test_value");
        testData.put("number", 42);

        exporter.exportToFile("test-export.json", testData);

        Path exportedFile = targetDir.resolve("test-export.json");
        assertTrue(Files.exists(exportedFile), "File should be exported");

        String content = Files.readString(exportedFile);
        assertFalse(content.isEmpty(), "File content should not be empty");

        Type mapType = new TypeToken<Map<String, Object>>(){
        }.getType();
        Map<String, Object> parsedData = gson.fromJson(content, mapType);
        assertEquals("test_value", parsedData.get("test_key"));
        assertEquals(42.0, parsedData.get("number"));
    }

    @Test
    void shouldUpdateAggregatedMetrics() throws Exception {
        Map<String, Object> benchmarkData1 = new HashMap<>();
        benchmarkData1.put("timestamp", "2025-01-01T10:00:00Z");
        benchmarkData1.put("sample_count", 1000);

        Map<String, Object> benchmarkData2 = new HashMap<>();
        benchmarkData2.put("timestamp", "2025-01-01T11:00:00Z");
        benchmarkData2.put("sample_count", 2000);

        exporter.updateAggregatedMetrics("aggregated.json", "benchmark1", benchmarkData1);
        exporter.updateAggregatedMetrics("aggregated.json", "benchmark2", benchmarkData2);

        Path aggregatedFile = targetDir.resolve("aggregated.json");
        assertTrue(Files.exists(aggregatedFile), "Aggregated metrics file should exist");

        String content = Files.readString(aggregatedFile);
        Type mapType = new TypeToken<Map<String, Object>>(){
        }.getType();
        Map<String, Object> parsedData = gson.fromJson(content, mapType);

        assertTrue(parsedData.containsKey("benchmark1"), "Should contain first benchmark");
        assertTrue(parsedData.containsKey("benchmark2"), "Should contain second benchmark");

        @SuppressWarnings("unchecked") Map<String, Object> benchmark1Data = (Map<String, Object>) parsedData.get("benchmark1");
        assertEquals(1000.0, benchmark1Data.get("sample_count"));

        @SuppressWarnings("unchecked") Map<String, Object> benchmark2Data = (Map<String, Object>) parsedData.get("benchmark2");
        assertEquals(2000.0, benchmark2Data.get("sample_count"));
    }

    @Test
    void shouldReadExistingMetrics() throws Exception {
        Map<String, Object> originalData = new HashMap<>();
        originalData.put("existing_key", "existing_value");
        originalData.put("number", 123);

        exporter.exportToFile("existing.json", originalData);

        Map<String, Object> readData = exporter.readExistingMetrics("existing.json");

        assertEquals(originalData.size(), readData.size());
        assertEquals("existing_value", readData.get("existing_key"));
        assertEquals(123.0, readData.get("number"));
    }

    @Test
    void shouldReturnEmptyMapForNonExistentFile() {
        Map<String, Object> readData = exporter.readExistingMetrics("non-existent.json");

        assertTrue(readData.isEmpty(), "Should return empty map for non-existent file");
    }

    @Test
    void shouldReturnEmptyMapForEmptyFile() throws Exception {
        Path emptyFile = targetDir.resolve("empty.json");
        Files.createFile(emptyFile);

        Map<String, Object> readData = exporter.readExistingMetrics("empty.json");

        assertTrue(readData.isEmpty(), "Should return empty map for empty file");
    }
}
