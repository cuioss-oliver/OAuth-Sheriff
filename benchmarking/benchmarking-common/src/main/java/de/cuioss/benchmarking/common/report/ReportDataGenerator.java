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

import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.constants.BenchmarkConstants;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.util.JsonSerializationHelper;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Files.Data.BENCHMARK_DATA_JSON;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Files.Directories.DATA_DIR;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Metrics.Modes.*;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Metrics.Percentiles.*;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Metrics.Units.OPS;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Metrics.Units.SUFFIX_OP;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Badge.MESSAGE;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.DateFormats.DISPLAY_TIMESTAMP_PATTERN;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Grades.CssClasses.GRADE_F;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.JsonFields.*;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Messages.HISTORICAL_DATA_NOT_AVAILABLE;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;

/**
 * Generates a standardized JSON data file containing all report data
 * that can be consumed by HTML templates via JavaScript.
 * <p>
 * This generator consolidates all benchmark data and metrics into a single
 * JSON file named "benchmark-data.json" that templates load and process.
 * <p>
 * The generated JSON structure includes:
 * <ul>
 *   <li>Metadata (timestamp, benchmark type, etc.)</li>
 *   <li>Overview metrics (totals, averages, grades)</li>
 *   <li>Detailed benchmark results</li>
 *   <li>Chart data for visualizations</li>
 *   <li>Trend data for historical analysis</li>
 * </ul>
 */
public class ReportDataGenerator {

    private static final CuiLogger LOGGER = new CuiLogger(ReportDataGenerator.class);
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private static final String DATA_FILE_NAME = BENCHMARK_DATA_JSON;

    private final TrendDataProcessor trendProcessor = new TrendDataProcessor();
    private final BadgeGenerator badgeGenerator = new BadgeGenerator();
    private final HistoricalDataManager historyManager = new HistoricalDataManager();

    /**
     * Generates a comprehensive data file for report templates using BenchmarkData.
     *
     * @param benchmarkData the benchmark data to generate reports from
     * @param type the benchmark type
     * @param outputDir the output directory
     * @throws IOException if writing fails
     */
    public void generateDataFile(BenchmarkData benchmarkData, BenchmarkType type, String outputDir)
            throws IOException {

        Map<String, Object> data = new LinkedHashMap<>();

        // Convert BenchmarkData to report format
        data.put(METADATA, convertMetadata(benchmarkData.getMetadata()));
        data.put(OVERVIEW, convertOverview(benchmarkData.getOverview()));
        data.put(BENCHMARKS, convertBenchmarks(benchmarkData.getBenchmarks()));
        data.put(CHART_DATA, createChartData(benchmarkData.getBenchmarks()));

        // Extract metrics for trend processing
        BenchmarkMetrics metrics = extractMetrics(benchmarkData.getOverview());
        data.put(TRENDS, createTrendData(outputDir, metrics));

        // Write data file to data subdirectory
        Path dataDir = Path.of(outputDir, DATA_DIR);
        Files.createDirectories(dataDir);
        Path dataFile = dataDir.resolve(DATA_FILE_NAME);
        Files.writeString(dataFile, JsonSerializationHelper.toJson(data));

        LOGGER.info(INFO.METRICS_FILE_GENERATED, dataFile);

        // Archive current run to history
        String commitSha = System.getenv("GITHUB_SHA");
        if (commitSha == null || commitSha.isEmpty()) {
            commitSha = "local-run";
        }
        historyManager.archiveCurrentRun(data, outputDir, commitSha);

        // Enforce retention policy
        Path historyDir = HistoricalDataManager.resolveHistoryDir(outputDir);
        historyManager.enforceRetentionPolicy(historyDir);

        // Generate badges
        TrendDataProcessor.TrendMetrics trendMetrics = null;
        if (historyManager.hasHistoricalData(outputDir)) {
            List<TrendDataProcessor.HistoricalDataPoint> historicalData =
                    trendProcessor.loadHistoricalData(historyDir);
            if (!historicalData.isEmpty()) {
                trendMetrics = trendProcessor.calculateTrends(metrics, historicalData);
            }
        }
        badgeGenerator.writeBadgeFiles(metrics, trendMetrics, type, outputDir);
    }

    private Map<String, Object> convertMetadata(BenchmarkData.Metadata metadata) {
        if (metadata == null) {
            return createDefaultMetadata();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(TIMESTAMP, metadata.getTimestamp());
        result.put(DISPLAY_TIMESTAMP, metadata.getDisplayTimestamp());
        result.put(BENCHMARK_TYPE, metadata.getBenchmarkType());
        result.put(BenchmarkConstants.Report.JsonFields.REPORT_VERSION, metadata.getReportVersion());
        result.put("projectName", metadata.getProjectName());
        return result;
    }

    private Map<String, Object> createDefaultMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        Instant now = Instant.now();
        metadata.put(TIMESTAMP, ISO_FORMATTER.format(now.atOffset(ZoneOffset.UTC)));
        metadata.put(DISPLAY_TIMESTAMP, DateTimeFormatter.ofPattern(DISPLAY_TIMESTAMP_PATTERN)
                .format(now.atOffset(ZoneOffset.UTC)));
        metadata.put(BENCHMARK_TYPE, BenchmarkType.MICRO.getDisplayName());
        metadata.put(BenchmarkConstants.Report.JsonFields.REPORT_VERSION, BenchmarkConstants.Report.Versions.REPORT_VERSION);
        metadata.put("projectName", null);
        return metadata;
    }

    private Map<String, Object> convertOverview(BenchmarkData.Overview overview) {
        if (overview == null) {
            return createDefaultOverview();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put(BenchmarkConstants.Report.JsonFields.THROUGHPUT, overview.getThroughput());
        result.put(LATENCY, overview.getLatency());
        // Archive the numeric values too: trend analysis reads these directly instead of
        // regex-parsing display strings (which silently mis-scales values like "1.5s")
        result.put("throughputOpsPerSec", overview.getThroughputOpsPerSec());
        result.put("latencyMs", overview.getLatencyMs());
        result.put(THROUGHPUT_BENCHMARK_NAME, overview.getThroughputBenchmarkName());
        result.put(LATENCY_BENCHMARK_NAME, overview.getLatencyBenchmarkName());
        result.put(PERFORMANCE_SCORE, overview.getPerformanceScore());
        result.put(PERFORMANCE_GRADE, overview.getPerformanceGrade());
        result.put(PERFORMANCE_GRADE_CLASS, overview.getPerformanceGradeClass());
        return result;
    }

    private Map<String, Object> createDefaultOverview() {
        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put(BenchmarkConstants.Report.JsonFields.THROUGHPUT, "N/A");
        overview.put(LATENCY, "N/A");
        overview.put(THROUGHPUT_BENCHMARK_NAME, "");
        overview.put(LATENCY_BENCHMARK_NAME, "");
        overview.put(PERFORMANCE_SCORE, 0);
        overview.put(PERFORMANCE_GRADE, "F");
        overview.put(PERFORMANCE_GRADE_CLASS, GRADE_F);
        return overview;
    }

    private BenchmarkMetrics extractMetrics(BenchmarkData.Overview overview) {
        if (overview == null) {
            return new BenchmarkMetrics("N/A", "N/A", 0.0, 0.0, 0, "F");
        }

        // Use numeric values directly from overview (no parsing needed!)
        double throughput = overview.getThroughputOpsPerSec() != null ? overview.getThroughputOpsPerSec() : 0.0;
        double latency = overview.getLatencyMs() != null ? overview.getLatencyMs() : 0.0;

        return new BenchmarkMetrics(
                overview.getThroughputBenchmarkName() != null ? overview.getThroughputBenchmarkName() : "N/A",
                overview.getLatencyBenchmarkName() != null ? overview.getLatencyBenchmarkName() : "N/A",
                throughput,
                latency,
                overview.getPerformanceScore(),
                overview.getPerformanceGrade() != null ? overview.getPerformanceGrade() : "F"
        );
    }


    private List<Map<String, Object>> convertBenchmarks(List<BenchmarkData.Benchmark> benchmarks) {
        if (benchmarks == null) {
            return new ArrayList<>();
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (BenchmarkData.Benchmark benchmark : benchmarks) {
            Map<String, Object> result = new LinkedHashMap<>();

            result.put(NAME, benchmark.getName());
            result.put(FULL_NAME, benchmark.getFullName());
            result.put(MODE, benchmark.getMode());
            result.put(SCORE, benchmark.getScore());
            result.put(SCORE_UNIT, benchmark.getScoreUnit());

            if (benchmark.getThroughput() != null) {
                result.put(BenchmarkConstants.Report.JsonFields.THROUGHPUT, benchmark.getThroughput());
            }
            if (benchmark.getLatency() != null) {
                result.put(BenchmarkConstants.Report.JsonFields.LATENCY, benchmark.getLatency());
            }

            result.put(ERROR, benchmark.getError());
            result.put(VARIABILITY_COEFFICIENT, benchmark.getVariabilityCoefficient());
            result.put(CONFIDENCE_LOW, benchmark.getConfidenceLow());
            result.put(CONFIDENCE_HIGH, benchmark.getConfidenceHigh());

            if (benchmark.getPercentiles() != null && !benchmark.getPercentiles().isEmpty()) {
                result.put(PERCENTILES, benchmark.getPercentiles());
            }

            results.add(result);
        }
        return results;
    }

    private Map<String, Object> createChartData(List<BenchmarkData.Benchmark> benchmarks) {
        if (benchmarks == null) {
            benchmarks = new ArrayList<>();
        }

        Map<String, Object> chartData = new LinkedHashMap<>();
        List<String> labels = new ArrayList<>();
        List<Double> throughput = new ArrayList<>();
        List<Double> latency = new ArrayList<>();

        for (BenchmarkData.Benchmark benchmark : benchmarks) {
            labels.add(benchmark.getName());

            // Extract throughput: use rawScore if mode is thrpt or scoreUnit contains "ops"
            Double throughputValue = null;
            if (BenchmarkConstants.Metrics.Modes.THROUGHPUT.equals(benchmark.getMode()) ||
                    (benchmark.getScoreUnit() != null && benchmark.getScoreUnit().contains(OPS))) {
                throughputValue = benchmark.getRawScore();
            }

            // Extract latency: Only for benchmarks that measure latency
            // - WRK benchmarks: mode=thrpt but percentiles represent latency (fullName starts with "wrk.")
            // - JMH latency benchmarks: mode=avgt/sample, use rawScore or percentiles
            // - JMH throughput benchmarks: mode=thrpt, percentiles are throughput variance (NOT latency!)
            Double latencyValue = null;
            if (hasLatencyPercentiles(benchmark)) {
                // WRK benchmarks or JMH latency benchmarks with percentiles - use P50 as latency
                latencyValue = benchmark.getPercentiles().get(P_50);
            } else if (AVERAGE_TIME.equals(benchmark.getMode()) || SAMPLE.equals(benchmark.getMode()) ||
                    (benchmark.getScoreUnit() != null && benchmark.getScoreUnit().contains(SUFFIX_OP))) {
                // JMH latency benchmarks without percentiles - use rawScore
                latencyValue = benchmark.getRawScore();
            }

            throughput.add(throughputValue);
            latency.add(latencyValue);
        }

        chartData.put(LABELS, labels);
        chartData.put(BenchmarkConstants.Report.JsonFields.THROUGHPUT, throughput);
        chartData.put(BenchmarkConstants.Report.JsonFields.LATENCY, latency);
        chartData.put(PERCENTILES_DATA, createPercentilesChartData(benchmarks));

        return chartData;
    }

    private Map<String, Object> createPercentilesChartData(List<BenchmarkData.Benchmark> benchmarks) {
        String[] percentileKeys = {P_0, P_50, P_90, P_95, P_99, P_99_9, P_99_99, P_100};
        List<String> percentileLabels = Arrays.asList(LABEL_P0, LABEL_P50, LABEL_P90, LABEL_P95, LABEL_P99, LABEL_P99_9, LABEL_P99_99, LABEL_P100);

        List<String> benchmarkNames = new ArrayList<>();
        Map<String, List<Double>> dataByBenchmark = new LinkedHashMap<>();

        collectPercentileData(benchmarks, percentileKeys, benchmarkNames, dataByBenchmark);

        Map<String, Object> percentilesChart = new LinkedHashMap<>();
        percentilesChart.put(PERCENTILE_LABELS, percentileLabels);
        percentilesChart.put(BenchmarkConstants.Report.JsonFields.BENCHMARKS, benchmarkNames);
        percentilesChart.put(DATA, dataByBenchmark);
        percentilesChart.put(LABELS, benchmarkNames);
        percentilesChart.put(DATASETS, createPercentileDatasets(percentileKeys, benchmarkNames, dataByBenchmark));

        return percentilesChart;
    }

    private void collectPercentileData(List<BenchmarkData.Benchmark> benchmarks, String[] percentileKeys,
            List<String> benchmarkNames, Map<String, List<Double>> dataByBenchmark) {
        if (benchmarks == null) {
            return;
        }

        for (BenchmarkData.Benchmark benchmark : benchmarks) {
            // Only include benchmarks with LATENCY percentiles (not throughput variance)
            // - WRK benchmarks: fullName starts with "wrk.", percentiles = latency distribution
            // - JMH latency benchmarks: mode=avgt/sample, percentiles = latency distribution
            // - JMH throughput benchmarks: mode=thrpt (non-WRK), percentiles = throughput variance (EXCLUDE)
            if (hasLatencyPercentiles(benchmark)) {
                benchmarkNames.add(benchmark.getName());
                List<Double> benchmarkData = extractPercentileValues(benchmark.getPercentiles(), percentileKeys);
                dataByBenchmark.put(benchmark.getName(), benchmarkData);
            }
        }
    }

    /**
     * Checks if a benchmark has latency percentiles (as opposed to throughput variance percentiles).
     * <p>
     * WRK benchmarks have mode=thrpt but their percentiles represent latency distribution.
     * JMH throughput benchmarks have mode=thrpt but their percentiles represent throughput iteration variance.
     * JMH latency benchmarks have mode=avgt/sample and their percentiles represent latency distribution.
     *
     * @param benchmark the benchmark to check
     * @return true if the benchmark has latency percentiles
     */
    private boolean hasLatencyPercentiles(BenchmarkData.Benchmark benchmark) {
        if (benchmark.getPercentiles() == null || !benchmark.getPercentiles().containsKey(P_50)) {
            return false;
        }

        // WRK benchmarks: fullName starts with "wrk." - these have latency percentiles
        String fullName = benchmark.getFullName();
        if (fullName != null && fullName.startsWith("wrk.")) {
            return true;
        }

        // JMH latency benchmarks: mode is avgt or sample - these have latency percentiles
        String mode = benchmark.getMode();
        return AVERAGE_TIME.equals(mode) || SAMPLE.equals(mode);
    }

    private List<Double> extractPercentileValues(Map<String, Double> percentiles, String[] percentileKeys) {
        List<Double> benchmarkData = new ArrayList<>();

        if (percentiles != null && !percentiles.isEmpty()) {
            for (String key : percentileKeys) {
                benchmarkData.add(percentiles.get(key));
            }
        } else {
            for (int i = 0; i < percentileKeys.length; i++) {
                benchmarkData.add(null);
            }
        }

        return benchmarkData;
    }

    private Map<String, List<Double>> createPercentileDatasets(String[] percentileKeys,
            List<String> benchmarkNames,
            Map<String, List<Double>> dataByBenchmark) {
        Map<String, List<Double>> datasets = new LinkedHashMap<>();

        for (int i = 0; i < percentileKeys.length; i++) {
            String percentileLabel = percentileKeys[i] + SUFFIX_TH;
            List<Double> percentileValues = extractValuesForPercentile(i, benchmarkNames, dataByBenchmark);
            datasets.put(percentileLabel, percentileValues);
        }

        return datasets;
    }

    private List<Double> extractValuesForPercentile(int percentileIndex, List<String> benchmarkNames,
            Map<String, List<Double>> dataByBenchmark) {
        List<Double> percentileValues = new ArrayList<>();

        for (String benchmarkName : benchmarkNames) {
            List<Double> benchmarkData = dataByBenchmark.get(benchmarkName);
            if (benchmarkData != null && percentileIndex < benchmarkData.size()) {
                percentileValues.add(benchmarkData.get(percentileIndex));
            } else {
                percentileValues.add(null);
            }
        }

        return percentileValues;
    }

    private Map<String, Object> createTrendData(String outputDir, BenchmarkMetrics metrics) {
        // Single resolution point: archive, retention and trends all use the same directory
        Path historyDir = HistoricalDataManager.resolveHistoryDir(outputDir);

        if (!Files.exists(historyDir)) {
            // First run, no history available
            LOGGER.info(INFO.HISTORY_DIR_NOT_FOUND, historyDir);
            return createNoHistoryResponse();
        }

        List<TrendDataProcessor.HistoricalDataPoint> historicalData =
                trendProcessor.loadHistoricalData(historyDir);

        if (historicalData.isEmpty()) {
            return createNoHistoryResponse();
        }

        TrendDataProcessor.TrendMetrics trendMetrics =
                trendProcessor.calculateTrends(metrics, historicalData);

        Map<String, Object> trendData = new LinkedHashMap<>();
        trendData.put(AVAILABLE, true);
        trendData.put("direction", trendMetrics.direction());
        trendData.put("changePercentage", trendMetrics.changePercentage());
        trendData.put("movingAverage", trendMetrics.movingAverage());
        trendData.put("throughputTrend", trendMetrics.throughputTrend());
        trendData.put("latencyTrend", trendMetrics.latencyTrend());
        trendData.put("chartData", trendProcessor.generateTrendChartData(historicalData, metrics));
        trendData.put("summary", generateTrendSummary(trendMetrics));

        return trendData;
    }

    private Map<String, Object> createNoHistoryResponse() {
        Map<String, Object> trends = new LinkedHashMap<>();
        trends.put(AVAILABLE, false);
        trends.put(MESSAGE, HISTORICAL_DATA_NOT_AVAILABLE);
        return trends;
    }

    private String generateTrendSummary(TrendDataProcessor.TrendMetrics trendMetrics) {
        String direction = trendMetrics.direction();
        double change = Math.abs(trendMetrics.changePercentage());

        if (BenchmarkConstants.Report.Badge.TrendDirection.STABLE.equals(direction)) {
            return BenchmarkConstants.Report.Messages.PERFORMANCE_STABLE_FORMAT.formatted(change);
        } else if (BenchmarkConstants.Report.Badge.TrendDirection.UP.equals(direction)) {
            return BenchmarkConstants.Report.Messages.PERFORMANCE_IMPROVED_FORMAT.formatted(change);
        } else {
            return BenchmarkConstants.Report.Messages.PERFORMANCE_DECREASED_FORMAT.formatted(change);
        }
    }

}