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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for TrendDataProcessor.
 */
class TrendDataProcessorTest {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    @Test
    void loadHistoricalDataFromEmptyDirectory(@TempDir Path tempDir) {
        TrendDataProcessor processor = new TrendDataProcessor();
        Path historyDir = tempDir.resolve("history");

        List<TrendDataProcessor.HistoricalDataPoint> data = processor.loadHistoricalData(historyDir);
        assertTrue(data.isEmpty());
    }

    @Test
    void loadHistoricalDataWithValidFiles(@TempDir Path tempDir) throws Exception {
        TrendDataProcessor processor = new TrendDataProcessor();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create test data files
        createTestHistoryFile(historyDir, "2025-01-10-T1200Z-abc123.json",
                1000.0, 50.0, 75.0);
        createTestHistoryFile(historyDir, "2025-01-11-T1200Z-def456.json",
                1100.0, 45.0, 80.0);
        createTestHistoryFile(historyDir, "2025-01-12-T1200Z-ghi789.json",
                1200.0, 40.0, 85.0);

        List<TrendDataProcessor.HistoricalDataPoint> data = processor.loadHistoricalData(historyDir);

        assertEquals(3, data.size());

        // Should be sorted newest first
        assertEquals(85.0, data.getFirst().performanceScore());
        assertEquals(80.0, data.get(1).performanceScore());
        assertEquals(75.0, data.get(2).performanceScore());
    }

    @Test
    void calculateTrendsNoHistory() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 1000.0, 50.0, 75.0, "B"
        );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, List.of()
        );

        assertEquals("stable", trends.direction());
        assertEquals(0.0, trends.changePercentage());
        assertEquals(75.0, trends.movingAverage());
    }

    @Test
    void calculateTrendsImprovement() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 1200.0, 40.0, 85.0, "A"
        );

        TrendDataProcessor.HistoricalDataPoint previousRun =
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-10-T1200Z", 1000.0, 50.0, 75.0, "abc123"
                );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, List.of(previousRun)
        );

        assertEquals("up", trends.direction());
        assertTrue(trends.changePercentage() > 0);
        assertEquals(20.0, trends.throughputTrend()); // 20% improvement
        assertEquals(-20.0, trends.latencyTrend()); // 20% better (lower is better)
    }

    @Test
    void calculateTrendsDecline() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 900.0, 60.0, 65.0, "C"
        );

        TrendDataProcessor.HistoricalDataPoint previousRun =
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-10-T1200Z", 1000.0, 50.0, 75.0, "abc123"
                );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, List.of(previousRun)
        );

        assertEquals("down", trends.direction());
        assertTrue(trends.changePercentage() < 0);
        assertEquals(-10.0, trends.throughputTrend()); // 10% worse
        assertEquals(20.0, trends.latencyTrend()); // 20% worse (higher is worse)
    }

    @Test
    void calculateTrendsStable() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 1010.0, 49.5, 75.5, "B"
        );

        TrendDataProcessor.HistoricalDataPoint previousRun =
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-10-T1200Z", 1000.0, 50.0, 75.0, "abc123"
                );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, List.of(previousRun)
        );

        // Small change (< 2%) should be considered stable
        assertEquals("stable", trends.direction());
        assertTrue(Math.abs(trends.changePercentage()) < 2.0);
    }

    @Test
    void movingAverage() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 1000.0, 50.0, 90.0, "A"
        );

        List<TrendDataProcessor.HistoricalDataPoint> history = List.of(
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-14-T1200Z", 1000.0, 50.0, 85.0, "d"
                ),
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-13-T1200Z", 1000.0, 50.0, 80.0, "c"
                ),
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-12-T1200Z", 1000.0, 50.0, 75.0, "b"
                ),
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-11-T1200Z", 1000.0, 50.0, 70.0, "a"
                )
        );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, history
        );

        // Moving average should be (90 + 85 + 80 + 75 + 70) / 5 = 80
        assertEquals(80.0, trends.movingAverage());
    }

    @Test
    void generateTrendChartData() {
        TrendDataProcessor processor = new TrendDataProcessor();
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "testBenchmark", "latencyBenchmark", 1200.0, 40.0, 90.0, "A"
        );

        List<TrendDataProcessor.HistoricalDataPoint> history = List.of(
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-12-T1200Z", 1100.0, 45.0, 85.0, "b"
                ),
                new TrendDataProcessor.HistoricalDataPoint(
                        "2025-01-11-T1200Z", 1000.0, 50.0, 80.0, "a"
                )
        );

        Map<String, Object> chartData = processor.generateTrendChartData(history, currentMetrics);

        assertNotNull(chartData);
        assertTrue(chartData.containsKey("timestamps"));
        assertTrue(chartData.containsKey("throughput"));
        assertTrue(chartData.containsKey("latency"));
        assertTrue(chartData.containsKey("performanceScores"));
        assertTrue(chartData.containsKey("statistics"));

        @SuppressWarnings("unchecked") List<String> timestamps = (List<String>) chartData.get("timestamps");
        assertEquals(3, timestamps.size()); // 2 historical + 1 current
        assertEquals("Current", timestamps.get(2));

        @SuppressWarnings("unchecked") List<Double> scores = (List<Double>) chartData.get("performanceScores");
        assertEquals(3, scores.size());
        assertEquals(80.0, scores.getFirst()); // Oldest first in chart
        assertEquals(85.0, scores.get(1));
        assertEquals(90.0, scores.get(2)); // Current
    }

    @Test
    void loadHistoricalDataWithCorruptFile(@TempDir Path tempDir) throws Exception {
        TrendDataProcessor processor = new TrendDataProcessor();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create valid file
        createTestHistoryFile(historyDir, "2025-01-10-T1200Z-abc123.json",
                1000.0, 50.0, 75.0);

        // Create corrupt file
        Files.writeString(historyDir.resolve("2025-01-11-T1200Z-bad.json"),
                "{ invalid json }");

        // Should handle corrupt file gracefully
        List<TrendDataProcessor.HistoricalDataPoint> data = processor.loadHistoricalData(historyDir);
        assertEquals(1, data.size()); // Only valid file loaded
    }

    @Test
    void maxHistoryEntries(@TempDir Path tempDir) throws Exception {
        TrendDataProcessor processor = new TrendDataProcessor();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create 15 test files
        for (int i = 1; i <= 15; i++) {
            String timestamp = "2025-01-%02d-T1200Z".formatted(i);
            createTestHistoryFile(historyDir, timestamp + "-test.json",
                    1000.0 + i, 50.0 - i, 70.0 + i);
        }

        List<TrendDataProcessor.HistoricalDataPoint> data = processor.loadHistoricalData(historyDir);

        // Should only load 10 most recent (MAX_HISTORY_ENTRIES = 10)
        assertEquals(10, data.size());

        // Verify it's the 10 newest
        assertEquals(85.0, data.getFirst().performanceScore()); // Day 15: 70+15=85
        assertEquals(84.0, data.get(1).performanceScore()); // Day 14: 70+14=84
    }

    @Test
    void calculateTrendsWithEWMAAfterMajorImprovement(@TempDir Path tempDir) throws Exception {
        // TEST: Verify EWMA detects improvement even when current score equals most recent history
        // Uses REAL benchmark data from /private/tmp/benchmark-verify/integration/history
        // Real scenario: scores were 28 for many runs, then jumped to 79, then stayed at 79
        // Previous logic: compared 79 vs 79 = 0% (misleading)
        // EWMA logic: compares 79 vs weighted average of (79, 28, 28, 28...) = significant improvement

        TrendDataProcessor processor = new TrendDataProcessor();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);

        // Create test data matching the real scenario from actual production benchmarks
        // This data represents: scores at 28 for many runs, then jumped to 79
        createTestHistoryFile(historyDir, "2025-10-09-T0606Z-e0fe8c83.json", 6700.0, 7.8, 79.0);
        createTestHistoryFile(historyDir, "2025-09-22-T1118Z-8547e8f3.json", 4000.0, 6.1, 28.0);
        createTestHistoryFile(historyDir, "2025-09-22-T0918Z-6e566f79.json", 3900.0, 6.1, 28.0);
        createTestHistoryFile(historyDir, "2025-09-22-T0856Z-139691b1.json", 3900.0, 6.2, 28.0);
        createTestHistoryFile(historyDir, "2025-09-22-T0819Z-1ade5619.json", 3800.0, 6.2, 27.0);
        createTestHistoryFile(historyDir, "2025-09-22-T0646Z-d9421a39.json", 3900.0, 6.1, 28.0);
        createTestHistoryFile(historyDir, "2025-09-22-T0606Z-bee5486d.json", 4000.0, 6.0, 28.0);
        createTestHistoryFile(historyDir, "2025-09-21-T2013Z-2085f04e.json", 4000.0, 6.1, 28.0);
        createTestHistoryFile(historyDir, "2025-09-20-T1434Z-adf2010b.json", 3900.0, 6.1, 28.0);

        List<TrendDataProcessor.HistoricalDataPoint> history = processor.loadHistoricalData(historyDir);

        // Current run: score 79 (same as most recent history)
        BenchmarkMetrics currentMetrics = new BenchmarkMetrics(
                "jwtValidation", "jwtValidation", 6634.17, 6.81, 79.0, "C"
        );

        TrendDataProcessor.TrendMetrics trends = processor.calculateTrends(
                currentMetrics, history
        );

        // With EWMA (λ=0.25), the baseline should be weighted heavily toward recent 79 but still
        // consider the older 28s:
        // EWMA baseline ≈ (79×1.0 + 28×0.25 + 28×0.0625 + 28×0.015625 + ...) / (1.0 + 0.25 + ...)
        //               ≈ (79 + 7 + 1.75 + 0.44 + ...) / (1.0 + 0.25 + 0.0625 + ...)
        //               ≈ 88 / 1.33 ≈ 66
        // Change: (79 - 66) / 66 ≈ +19.7%

        // The trend should show improvement, NOT stable at 0%
        assertEquals("up", trends.direction(),
                "EWMA should detect improvement comparing 79 vs weighted baseline of 28s");

        // Change should be significantly positive (at least 10%)
        assertTrue(trends.changePercentage() > 10.0,
                "Change percentage should be >10% when comparing 79 vs EWMA baseline, got: "
                        + trends.changePercentage());

        // Verify it's not the old buggy behavior (0% when comparing 79 vs 79)
        assertNotEquals(0.0, trends.changePercentage(), 0.1,
                "EWMA should NOT return 0% when history contains lower scores");
    }

    private void createTestHistoryFile(Path historyDir, String filename,
            double throughput, double latency,
            double performanceScore) throws IOException {
        Map<String, Object> data = new HashMap<>();

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("timestamp", filename.substring(0, filename.indexOf('-', 11)));
        data.put("metadata", metadata);

        Map<String, Object> overview = new HashMap<>();
        overview.put("throughput", throughput + " ops/s");
        overview.put("latency", latency + " ms");
        overview.put("performanceScore", performanceScore);
        data.put("overview", overview);

        String json = GSON.toJson(data);
        Files.writeString(historyDir.resolve(filename), json);
    }
}