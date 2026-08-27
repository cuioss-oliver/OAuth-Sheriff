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
package de.cuioss.benchmarking.common.converter;

import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.report.MetricConversionUtil;
import de.cuioss.benchmarking.common.report.MetricsComputer;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.ERROR.FAILED_PARSE_WRK_FILE;

/**
 * Converts WRK benchmark output to the central BenchmarkData model
 */
@SuppressWarnings("java:S5852") // ok for test-data
public class WrkBenchmarkConverter implements BenchmarkConverter {

    private static final CuiLogger LOGGER = new CuiLogger(WrkBenchmarkConverter.class);

    /** Key for the wrk-reported average latency (ms) in {@link BenchmarkData.Benchmark#getAdditionalData()}. */
    static final String LATENCY_AVG_MS = "latencyAvgMs";

    // Regex patterns for parsing WRK output
    private static final Pattern REQUESTS_PER_SEC = Pattern.compile("Requests/sec:\\s+([\\d.]+)");
    private static final Pattern LATENCY_STATS = Pattern.compile(
            "Latency\\s+([\\d.]+)(\\w+)\\s+([\\d.]+)(\\w+)\\s+([\\d.]+)(\\w+)\\s+([\\d.]+)%");
    private static final Pattern LATENCY_PERCENTILE = Pattern.compile(
            "\\s+(\\d+(?:\\.\\d+)?)%\\s+([\\d.]+)(\\w+)");

    @Override
    public BenchmarkData convert(Path sourcePath) throws IOException {
        if (sourcePath.toFile().isDirectory()) {
            // Convert all WRK output files in directory
            return convertDirectory(sourcePath);
        } else {
            // Convert single WRK output file
            return convertFile(sourcePath);
        }
    }

    private BenchmarkData convertDirectory(Path dir) throws IOException {
        List<BenchmarkData.Benchmark> benchmarks = new ArrayList<>();

        // Process all .txt files in the directory (should only contain WRK results)
        try (var stream = Files.list(dir)) {
            stream.filter(p -> p.getFileName().toString().endsWith(".txt"))
                    .forEach(file -> {
                        try {
                            LOGGER.debug("Processing WRK result file: " + file.getFileName());
                            BenchmarkData.Benchmark benchmark = parseWrkFile(file);
                            if (benchmark != null) {
                                benchmarks.add(benchmark);
                            }
                        } catch (IOException e) {
                            LOGGER.error(e, FAILED_PARSE_WRK_FILE, file);
                        }
                    });
        }

        return BenchmarkData.builder()
                .metadata(createMetadata())
                .overview(createOverview(benchmarks))
                .benchmarks(benchmarks)
                .build();
    }

    private BenchmarkData convertFile(Path file) throws IOException {
        BenchmarkData.Benchmark benchmark = parseWrkFile(file);
        List<BenchmarkData.Benchmark> benchmarks = benchmark != null ?
                List.of(benchmark) : List.of();

        return BenchmarkData.builder()
                .metadata(createMetadata())
                .overview(createOverview(benchmarks))
                .benchmarks(benchmarks)
                .build();
    }

    /**
     * Parses a single WRK output file into a benchmark.
     *
     * @param file the WRK output file
     * @return the parsed benchmark, or {@code null} if the file contains no parseable
     *         {@code Requests/sec} line (the caller must skip such files)
     * @throws IOException if reading the file fails
     */
    private BenchmarkData.Benchmark parseWrkFile(Path file) throws IOException {
        String content = Files.readString(file);
        String name = extractBenchmarkName(file);

        // Parse requests per second (throughput) - without it the file yields no usable metrics
        Matcher m = REQUESTS_PER_SEC.matcher(content);
        if (!m.find()) {
            LOGGER.error(FAILED_PARSE_WRK_FILE, file);
            return null;
        }
        double requestsPerSec = Double.parseDouble(m.group(1));

        // Parse latency statistics
        double latencyAvg = 0;
        double latencyStdev = 0;
        m = LATENCY_STATS.matcher(content);
        if (m.find()) {
            latencyAvg = convertToMs(Double.parseDouble(m.group(1)), m.group(2));
            latencyStdev = convertToMs(Double.parseDouble(m.group(3)), m.group(4));
        }

        // Parse percentiles - only measured values are reported, missing percentiles
        // are NOT estimated/fabricated. Downstream consumers tolerate missing keys.
        Map<String, Double> percentiles = new LinkedHashMap<>();
        m = LATENCY_PERCENTILE.matcher(content);
        while (m.find()) {
            double percentile = Double.parseDouble(m.group(1));
            double value = convertToMs(Double.parseDouble(m.group(2)), m.group(3));
            percentiles.put(String.valueOf(percentile), value);
        }

        return BenchmarkData.Benchmark.builder()
                .name(name)
                .fullName("wrk." + name)
                .mode("thrpt")
                .rawScore(requestsPerSec)
                .score(MetricConversionUtil.formatWrkThroughput(requestsPerSec))
                .scoreUnit("ops/s")
                .throughput(MetricConversionUtil.formatWrkThroughput(requestsPerSec))
                .latency(MetricConversionUtil.formatWrkLatency(latencyAvg))
                .error(latencyStdev)
                .variabilityCoefficient(latencyAvg > 0 ? (latencyStdev / latencyAvg * 100) : 0)
                .confidenceLow(Math.max(0, latencyAvg - latencyStdev))
                .confidenceHigh(latencyAvg + latencyStdev)
                .percentiles(percentiles)
                .additionalData(Map.of(LATENCY_AVG_MS, latencyAvg))
                .build();
    }

    private String extractBenchmarkName(Path file) {
        String fileName = file.getFileName().toString();

        // First, try to extract from embedded metadata if available
        try {
            List<String> lines = Files.readAllLines(file);
            for (String line : lines) {
                if (line.startsWith("benchmark_name: ")) {
                    return line.substring(16).trim();
                }
                // Stop looking after WRK output starts
                if ("=== WRK OUTPUT ===".equals(line)) {
                    break;
                }
            }
        } catch (IOException e) {
            LOGGER.debug("Could not read metadata from file: " + file, e);
        }

        // Fallback to filename-based extraction
        if (fileName.contains("jwt")) {
            return "jwtValidation";
        } else if (fileName.contains("health-live")) {
            return "healthLiveCheck";
        } else if (fileName.contains("health")) {
            return "healthCheck";
        }
        return fileName.replace("-results.txt", "").replace("wrk-", "").replace("-output", "");
    }

    private double convertToMs(double value, String unit) {
        return switch (unit.toLowerCase()) {
            case "us" -> value / 1000.0;
            case "s" -> value * 1000.0;
            case "m" -> value * 60000.0;
            default -> value; // Handles "ms" and any other units as-is
        };
    }

    private BenchmarkData.Metadata createMetadata() {
        return ReportMetadataFactory.createMetadata(BenchmarkType.INTEGRATION.getDisplayName(), null);
    }

    private BenchmarkData.Overview createOverview(List<BenchmarkData.Benchmark> benchmarks) {
        // Find JWT benchmark (primary)
        BenchmarkData.Benchmark primary = benchmarks.stream()
                .filter(b -> b.getName().contains("jwt") || b.getName().contains("Validation"))
                .findFirst()
                .orElse(benchmarks.isEmpty() ? null : benchmarks.getFirst());

        if (primary == null) {
            return BenchmarkData.Overview.builder()
                    .throughput("N/A")
                    .latency("N/A")
                    .throughputOpsPerSec(0.0)
                    .latencyMs(0.0)
                    .performanceScore(0)
                    .performanceGrade("F")
                    .performanceGradeClass("grade-f")
                    .build();
        }

        double throughput = primary.getRawScore();
        double latencyMs = resolveLatencyMs(primary);
        // Delegate to MetricsComputer - the single home for score/grade computation
        int score = MetricsComputer.computeIntegrationScore(throughput, latencyMs);
        String grade = MetricsComputer.gradeIntegration(score);

        return BenchmarkData.Overview.builder()
                .throughput(primary.getThroughput())
                .latency(primary.getLatency())
                .throughputOpsPerSec(throughput)  // Store numeric value used for score calculation
                .latencyMs(latencyMs)             // Store numeric value used for score calculation
                .throughputBenchmarkName(primary.getName())
                .latencyBenchmarkName(primary.getName())
                .performanceScore(score)
                .performanceGrade(grade)
                .performanceGradeClass("grade-" + grade.toLowerCase())
                .build();
    }


    /**
     * Resolves the latency (in milliseconds) for the overview from measured data only:
     * the measured P50 percentile if present, otherwise the wrk-reported average latency.
     *
     * @param benchmark the primary benchmark
     * @return the measured latency in milliseconds, or 0 if neither value was reported
     */
    private double resolveLatencyMs(BenchmarkData.Benchmark benchmark) {
        if (benchmark.getPercentiles() != null && benchmark.getPercentiles().containsKey("50.0")) {
            return benchmark.getPercentiles().get("50.0");
        }
        if (benchmark.getAdditionalData() != null
                && benchmark.getAdditionalData().get(LATENCY_AVG_MS) instanceof Double avg) {
            return avg;
        }
        return 0;
    }
}