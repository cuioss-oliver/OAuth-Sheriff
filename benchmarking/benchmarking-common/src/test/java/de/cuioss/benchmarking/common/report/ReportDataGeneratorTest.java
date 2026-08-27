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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.util.JsonSerializationHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ReportDataGenerator, focusing on chart data generation with real benchmark data.
 */
class ReportDataGeneratorTest {

    @Test
    void chartDataGenerationWithRealIntegrationBenchmarks() throws Exception {
        // TEST: Reproduce the issue where latency and percentiles are missing from chart data
        // Uses REAL benchmark data from integration tests that has thrpt mode WITH latency/percentiles

        // Load real benchmark-data.json from test resources
        Path realDataPath = Path.of("src/test/resources/integration-benchmark-results/real-benchmark-data.json");
        assertTrue(Files.exists(realDataPath), "Real benchmark data file must exist: " + realDataPath);

        String jsonContent = Files.readString(realDataPath);

        // Deserialize to BenchmarkData model
        BenchmarkData benchmarkData = JsonSerializationHelper.fromJson(jsonContent, BenchmarkData.class);

        assertNotNull(benchmarkData, "Benchmark data should not be null");
        assertNotNull(benchmarkData.getBenchmarks(), "Benchmarks list should not be null");
        assertFalse(benchmarkData.getBenchmarks().isEmpty(), "Should have at least one benchmark");

        // Verify the jwtValidation benchmark has the expected structure
        BenchmarkData.Benchmark jwtBenchmark = benchmarkData.getBenchmarks().stream()
                .filter(b -> "jwtValidation".equals(b.getName()))
                .findFirst()
                .orElse(null);

        assertNotNull(jwtBenchmark, "jwtValidation benchmark must exist");
        assertEquals("thrpt", jwtBenchmark.getMode(), "Should be throughput mode");
        assertNotNull(jwtBenchmark.getLatency(), "Latency data should exist for WRK benchmark");
        assertNotNull(jwtBenchmark.getPercentiles(), "Percentiles should exist for WRK benchmark");
        assertFalse(jwtBenchmark.getPercentiles().isEmpty(), "Percentiles should not be empty");

        // VERIFICATION: Check that the real data has latency despite being thrpt mode
        // This is the core issue: thrpt mode benchmarks from WRK have BOTH throughput AND latency
        assertTrue(jwtBenchmark.getLatency().contains("ms"),
                "Latency should be in milliseconds format, got: " + jwtBenchmark.getLatency());

        // NOW PROCESS THE DATA WITH THE REPORTDATAGENERATOR TO GENERATE CHART DATA
        ReportDataGenerator generator = new ReportDataGenerator();
        java.lang.reflect.Method createChartDataMethod = ReportDataGenerator.class.getDeclaredMethod(
                "createChartData", List.class);
        createChartDataMethod.setAccessible(true);

        @SuppressWarnings("unchecked") Map<String, Object> chartData = (Map<String, Object>) createChartDataMethod.invoke(
                generator, benchmarkData.getBenchmarks());

        assertNotNull(chartData, "Chart data should be generated");

        // AFTER FIX: The latency array should have actual values
        @SuppressWarnings("unchecked") List<Double> latencyList = (List<Double>) chartData.get("latency");
        assertNotNull(latencyList, "Latency list should exist");

        // Find the jwtValidation index
        @SuppressWarnings("unchecked") List<String> labelsList = (List<String>) chartData.get("labels");
        int jwtIndex = labelsList.indexOf("jwtValidation");
        assertTrue(jwtIndex >= 0, "jwtValidation should be in labels");

        // AFTER FIX: latency should have actual value from the benchmark's P50 percentile
        Double latencyValue = latencyList.get(jwtIndex);
        assertNotNull(latencyValue, "FIXED: Latency should NOT be null when benchmark has percentile data");
        assertTrue(latencyValue > 0, "Latency value should be positive, got: " + latencyValue);

        // AFTER FIX: jwtValidation should be in percentiles data
        @SuppressWarnings("unchecked") Map<String, Object> percentilesData = (Map<String, Object>) chartData.get("percentilesData");
        assertNotNull(percentilesData, "Percentiles data should exist");

        @SuppressWarnings("unchecked") List<String> benchmarkNames = (List<String>) percentilesData.get("benchmarks");

        // FIXED: jwtValidation should be in the percentiles benchmarks list
        assertTrue(benchmarkNames.contains("jwtValidation"),
                "FIXED: jwtValidation should be in percentiles data when it has percentile info");

        // Verify percentile values are actually present
        @SuppressWarnings("unchecked") Map<String, List<Double>> datasets = (Map<String, List<Double>>) percentilesData.get("datasets");
        assertNotNull(datasets, "Datasets should exist");

        List<Double> p50Values = datasets.get("50.0th");
        assertNotNull(p50Values, "P50 values should exist");
        assertFalse(p50Values.isEmpty(), "Should have at least one percentile value");
    }

    @Test
    void nullOverviewProducesFGradeReportWithoutException(@TempDir Path tempDir) throws Exception {
        // Failed runs (null/empty overview, no benchmarks) must produce a degraded
        // F-grade report instead of crashing report generation (H-6)
        BenchmarkData degraded = BenchmarkData.builder()
                .metadata(null)
                .overview(null)
                .benchmarks(List.of())
                .build();

        ReportDataGenerator generator = new ReportDataGenerator();
        assertDoesNotThrow(() ->
                generator.generateDataFile(degraded, BenchmarkType.INTEGRATION, tempDir.toString()));

        Path dataFile = tempDir.resolve("data/benchmark-data.json");
        assertTrue(Files.exists(dataFile), "Degraded report data file must be written");

        JsonObject json = JsonParser.parseString(Files.readString(dataFile)).getAsJsonObject();
        JsonObject overview = json.getAsJsonObject("overview");
        assertEquals("F", overview.get("performanceGrade").getAsString(),
                "Degraded report must carry an F grade");
        assertEquals(0, overview.get("performanceScore").getAsInt());
        assertEquals("N/A", overview.get("throughput").getAsString());
        assertEquals("N/A", overview.get("latency").getAsString());
    }

    @Test
    void missingPercentileKeysAreTolerated() throws Exception {
        // WRK reports only measured percentiles (e.g. 50/75/90/99); the chart data must
        // tolerate missing standard keys instead of requiring fabricated values (H-5)
        BenchmarkData.Benchmark benchmark = BenchmarkData.Benchmark.builder()
                .name("jwtValidation")
                .fullName("wrk.jwtValidation")
                .mode("thrpt")
                .rawScore(10000.0)
                .score("10.0K ops/s")
                .scoreUnit("ops/s")
                .percentiles(Map.of(
                        "50.0", 1.5,
                        "75.0", 2.0,
                        "90.0", 3.5,
                        "99.0", 9.0))
                .build();

        ReportDataGenerator generator = new ReportDataGenerator();
        java.lang.reflect.Method createChartDataMethod = ReportDataGenerator.class.getDeclaredMethod(
                "createChartData", List.class);
        createChartDataMethod.setAccessible(true);

        @SuppressWarnings("unchecked") Map<String, Object> chartData =
                (Map<String, Object>) assertDoesNotThrow(() ->
                        createChartDataMethod.invoke(generator, List.of(benchmark)));

        @SuppressWarnings("unchecked") Map<String, Object> percentilesData =
                (Map<String, Object>) chartData.get("percentilesData");
        @SuppressWarnings("unchecked") Map<String, List<Double>> dataByBenchmark =
                (Map<String, List<Double>>) percentilesData.get("data");

        List<Double> values = dataByBenchmark.get("jwtValidation");
        assertNotNull(values, "Benchmark with P50 must be included in percentile chart data");

        // Keys: 0.0, 50.0, 90.0, 95.0, 99.0, 99.9, 99.99, 100.0
        assertNull(values.getFirst(), "Unmeasured P0 must be null, not fabricated");
        assertEquals(1.5, values.get(1), "Measured P50 must be present");
        assertEquals(3.5, values.get(2), "Measured P90 must be present");
        assertNull(values.get(3), "Unmeasured P95 must be null, not fabricated");
        assertEquals(9.0, values.get(4), "Measured P99 must be present");
        assertNull(values.get(5), "Unmeasured P99.9 must be null, not fabricated");
        assertNull(values.get(7), "Unmeasured P100 must be null, not fabricated");
    }
}
