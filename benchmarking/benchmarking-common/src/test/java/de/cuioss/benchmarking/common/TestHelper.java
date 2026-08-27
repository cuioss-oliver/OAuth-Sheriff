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
package de.cuioss.benchmarking.common;

import com.google.gson.*;
import de.cuioss.benchmarking.common.report.BenchmarkMetrics;
import de.cuioss.benchmarking.common.report.MetricsComputer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static de.cuioss.benchmarking.common.TestConstants.DEFAULT_LATENCY_BENCHMARK;
import static de.cuioss.benchmarking.common.TestConstants.DEFAULT_THROUGHPUT_BENCHMARK;

/**
 * Helper methods for tests.
 */
public final class TestHelper {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeSpecialFloatingPointValues()
            .create();

    private TestHelper() {
        // utility class
    }

    /**
     * Creates test metrics from a JSON file.
     * Automatically detects the throughput and latency benchmarks from the JSON data.
     */
    public static BenchmarkMetrics createTestMetrics(Path jsonFile) throws IOException {
        String jsonContent = Files.readString(jsonFile);
        JsonArray benchmarks = GSON.fromJson(jsonContent, JsonArray.class);

        // Auto-detect benchmark names from the JSON data
        String throughputBenchmark = findThroughputBenchmark(benchmarks);
        String latencyBenchmark = findLatencyBenchmark(benchmarks);

        MetricsComputer computer = new MetricsComputer(throughputBenchmark, latencyBenchmark);
        return computer.computeMetrics(benchmarks);
    }

    /**
     * Creates test metrics from a JSON file with specific benchmark names.
     */
    public static BenchmarkMetrics createTestMetrics(Path jsonFile, String throughputBenchmark, String latencyBenchmark)
            throws IOException {
        String jsonContent = Files.readString(jsonFile);
        JsonArray benchmarks = GSON.fromJson(jsonContent, JsonArray.class);

        MetricsComputer computer = new MetricsComputer(throughputBenchmark, latencyBenchmark);
        return computer.computeMetrics(benchmarks);
    }

    /**
     * Creates test metrics with specific values.
     */
    public static BenchmarkMetrics createTestMetrics(double throughput, double latency) {
        double rawPerformanceScore = (throughput / 100.0) * 0.5 + (100.0 / latency) * 0.5;
        double performanceScore = Math.round(rawPerformanceScore);
        String grade = getGrade(performanceScore);

        return new BenchmarkMetrics(
                DEFAULT_THROUGHPUT_BENCHMARK,
                DEFAULT_LATENCY_BENCHMARK,
                throughput,
                latency,
                performanceScore,
                grade
        );
    }

    private static String getGrade(double score) {
        if (score >= 95) return "A+";
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "F";
    }


    /**
     * Finds a throughput benchmark from the JSON array.
     * Prioritizes benchmarks with "measureThroughput" in the name, then any "thrpt" mode benchmark.
     */
    private static String findThroughputBenchmark(JsonArray benchmarks) {
        // First, look for benchmark containing "measureThroughput"
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String name = benchmark.get("benchmark").getAsString();
            String mode = benchmark.get("mode").getAsString();

            if (name.contains("measureThroughput") && "thrpt".equals(mode)) {
                // Extract just the method name part after the last dot
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // If not found, look for any throughput benchmark name with mode thrpt
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String name = benchmark.get("benchmark").getAsString();
            String mode = benchmark.get("mode").getAsString();

            if ("thrpt".equals(mode) && name.toLowerCase().contains("throughput")) {
                // Extract just the method name part after the last dot
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // Last resort: any thrpt mode benchmark
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String mode = benchmark.get("mode").getAsString();

            if ("thrpt".equals(mode)) {
                String name = benchmark.get("benchmark").getAsString();
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // Fallback to default if not found
        return DEFAULT_THROUGHPUT_BENCHMARK;
    }

    /**
     * Finds a latency benchmark from the JSON array.
     * Prioritizes benchmarks with "measureAverageTime" or "measureLatency", then any "avgt" mode benchmark.
     */
    private static String findLatencyBenchmark(JsonArray benchmarks) {
        // First, look for specific latency benchmark names
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String name = benchmark.get("benchmark").getAsString();
            String mode = benchmark.get("mode").getAsString();

            if ((name.contains("measureAverageTime") || name.contains("measureLatency")) &&
                    ("avgt".equals(mode) || "sample".equals(mode))) {
                // Extract just the method name part after the last dot
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // If not found, look for any benchmark with average/latency in name
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String name = benchmark.get("benchmark").getAsString();
            String mode = benchmark.get("mode").getAsString();

            if (("avgt".equals(mode) || "sample".equals(mode)) &&
                    (name.toLowerCase().contains("average") || name.toLowerCase().contains("latency"))) {
                // Extract just the method name part after the last dot
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // Last resort: any avgt or sample mode benchmark
        for (JsonElement element : benchmarks) {
            JsonObject benchmark = element.getAsJsonObject();
            String mode = benchmark.get("mode").getAsString();

            if ("avgt".equals(mode) || "sample".equals(mode)) {
                String name = benchmark.get("benchmark").getAsString();
                int lastDot = name.lastIndexOf('.');
                return lastDot >= 0 ? name.substring(lastDot + 1) : name;
            }
        }

        // Fallback to default if not found
        return DEFAULT_LATENCY_BENCHMARK;
    }
}