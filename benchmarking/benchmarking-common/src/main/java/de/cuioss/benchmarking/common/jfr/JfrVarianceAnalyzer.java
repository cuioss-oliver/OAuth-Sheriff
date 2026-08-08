/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.benchmarking.common.jfr;

import de.cuioss.benchmarking.common.report.StatisticsCalculator;
import de.cuioss.tools.logging.CuiLogger;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.ERROR.JFR_VARIANCE_USAGE;

/**
 * Analyzes JFR recordings to extract operation variance metrics.
 * <p>
 * This utility reads JFR files generated during benchmarks and calculates:
 * <ul>
 *   <li>Time variance across different operations</li>
 *   <li>Percentile distributions (P50, P95, P99)</li>
 *   <li>Coefficient of variation for operation times</li>
 *   <li>Concurrent load impact on variance</li>
 * </ul>
 * <p>
 * Usage:
 * <pre>{@code
 * Path jfrFile = Path.of("target/benchmark-results/benchmark.jfr");
 * JfrVarianceAnalyzer analyzer = new JfrVarianceAnalyzer();
 * VarianceReport report = analyzer.analyze(jfrFile);
 * report.printSummary();
 * }</pre>
 */
public class JfrVarianceAnalyzer {

    private static final CuiLogger LOGGER = new CuiLogger(JfrVarianceAnalyzer.class);

    /**
     * Analyzes a JFR recording file and generates a variance report.
     *
     * @param jfrFile path to the JFR recording file
     * @return variance analysis report
     * @throws IOException if the file cannot be read
     */
    public VarianceReport analyze(Path jfrFile) throws IOException {
        VarianceReport report = new VarianceReport();

        try (RecordingFile recordingFile = new RecordingFile(jfrFile)) {
            while (recordingFile.hasMoreEvents()) {
                RecordedEvent event = recordingFile.readEvent();

                if ("de.cuioss.benchmark.Operation".equals(event.getEventType().getName())) {
                    processOperationEvent(event, report);
                } else if ("de.cuioss.benchmark.OperationStatistics".equals(event.getEventType().getName())) {
                    processStatisticsEvent(event, report);
                }
            }
        }

        report.computeFinalStatistics();
        return report;
    }

    private void processOperationEvent(RecordedEvent event, VarianceReport report) {
        String benchmarkName = event.getString("benchmarkName");
        String operationType = event.getString("operationType");
        Duration duration = event.getDuration();
        boolean success = event.getBoolean("success");
        int concurrentOps = event.getInt("concurrentOperations");

        OperationMetrics metrics = report.getOrCreateMetrics(benchmarkName, operationType);
        metrics.addOperation(duration.toNanos(), success, concurrentOps);
    }

    private void processStatisticsEvent(RecordedEvent event, VarianceReport report) {
        String benchmarkName = event.getString("benchmarkName");
        String operationType = event.getString("operationType");

        StatisticsSnapshot snapshot = new StatisticsSnapshot();
        snapshot.sampleCount = event.getLong("sampleCount");
        snapshot.p50Latency = event.getDuration("p50Latency").toNanos();
        snapshot.p95Latency = event.getDuration("p95Latency").toNanos();
        snapshot.p99Latency = event.getDuration("p99Latency").toNanos();
        snapshot.variance = event.getDouble("variance");
        snapshot.coefficientOfVariation = event.getDouble("coefficientOfVariation");
        snapshot.concurrentThreads = event.getInt("concurrentThreads");

        OperationMetrics metrics = report.getOrCreateMetrics(benchmarkName, operationType);
        metrics.addStatisticsSnapshot(snapshot);
    }

    /**
     * Variance analysis report containing metrics for all operations.
     */
    public static class VarianceReport {
        private final Map<String, OperationMetrics> operationMetrics = new HashMap<>();

        OperationMetrics getOrCreateMetrics(String benchmarkName, String operationType) {
            String key = benchmarkName + ":" + operationType;
            return operationMetrics.computeIfAbsent(key, k -> new OperationMetrics(benchmarkName, operationType));
        }

        void computeFinalStatistics() {
            operationMetrics.values().forEach(OperationMetrics::computeStatistics);
        }

        /**
         * Prints a summary of the variance analysis to stdout.
         */
        // cui-rewrite:disable CuiLogRecordPatternRecipe
        // cui-rewrite:disable CuiLoggerStandardsRecipe
        // This is a CLI analysis tool that outputs formatted reports to console.
        // CuiLoggerStandardsRecipe is disabled because it misreads the argument-less
        // %n conversion as a value placeholder and rewrites it to %s, corrupting these
        // format strings — see https://github.com/cuioss/cui-open-rewrite/issues/135
        public void printSummary() {
            LOGGER.info("\n=== JFR Variance Analysis Report ===\n");

            operationMetrics.values().stream()
                    .sorted(Comparator.comparing(m -> m.benchmarkName))
                    .forEach(metrics -> {
                        // Report output - suppressed from LogRecord requirements
                        LOGGER.info("Benchmark: %s - Operation: %s%n",
                                metrics.benchmarkName, metrics.operationType);
                        LOGGER.info("  Total Operations: %s (Success: %s, Failed: %s)%n",
                                metrics.totalOperations, metrics.successfulOperations, metrics.failedOperations);
                        LOGGER.info("  Latency (μs) - P50: %s, P95: %s, P99: %s, Max: %s%n",
                                String.format(Locale.US, "%.2f", metrics.p50Latency / 1000.0),
                                String.format(Locale.US, "%.2f", metrics.p95Latency / 1000.0),
                                String.format(Locale.US, "%.2f", metrics.p99Latency / 1000.0),
                                String.format(Locale.US, "%.2f", metrics.maxLatency / 1000.0));
                        LOGGER.info("  Variance: %s ns² (StdDev: %s μs)%n",
                                String.format(Locale.US, "%.2e", metrics.variance),
                                String.format(Locale.US, "%.2f", metrics.standardDeviation / 1000.0));
                        LOGGER.info("  Coefficient of Variation: %s%%%n",
                                String.format(Locale.US, "%.2f", metrics.coefficientOfVariation));
                        LOGGER.info("  Max Concurrent Operations: %s%n", metrics.maxConcurrentOperations);

                        if (!metrics.statisticsSnapshots.isEmpty()) {
                            LOGGER.info("  Periodic Statistics:");
                            LOGGER.info("    Average CV over time: %s%%%n",
                                    String.format(Locale.US, "%.2f", metrics.averageCV));
                            LOGGER.info("    CV Range: %s%% - %s%%%n",
                                    String.format(Locale.US, "%.2f", metrics.minCV),
                                    String.format(Locale.US, "%.2f", metrics.maxCV));
                        }

                        LOGGER.info("");
                    });
        }

    }

    /**
     * Metrics for a specific operation type within a benchmark.
     */
    public static class OperationMetrics {
        final String benchmarkName;
        final String operationType;

        // Raw operation data
        final List<Long> operationDurations = new ArrayList<>();
        long totalOperations = 0;
        long successfulOperations = 0;
        long failedOperations = 0;
        int maxConcurrentOperations = 0;

        // Computed statistics
        double p50Latency = 0;
        double p95Latency = 0;
        double p99Latency = 0;
        double maxLatency = 0;
        double variance = 0;
        double standardDeviation = 0;
        double coefficientOfVariation = 0;

        // Periodic statistics
        final List<StatisticsSnapshot> statisticsSnapshots = new ArrayList<>();
        double averageCV = 0;
        double minCV = Double.MAX_VALUE;
        double maxCV = 0;

        OperationMetrics(String benchmarkName, String operationType) {
            this.benchmarkName = benchmarkName;
            this.operationType = operationType;
        }

        void addOperation(long durationNanos, boolean success, int concurrentOps) {
            operationDurations.add(durationNanos);
            totalOperations++;
            if (success) {
                successfulOperations++;
            } else {
                failedOperations++;
            }
            maxConcurrentOperations = Math.max(maxConcurrentOperations, concurrentOps);
        }

        void addStatisticsSnapshot(StatisticsSnapshot snapshot) {
            statisticsSnapshots.add(snapshot);
            minCV = Math.min(minCV, snapshot.coefficientOfVariation);
            maxCV = Math.max(maxCV, snapshot.coefficientOfVariation);
        }

        void computeStatistics() {
            if (operationDurations.isEmpty()) {
                return;
            }

            // Sort durations for percentile calculation
            Collections.sort(operationDurations);

            // Delegate to the shared statistics home (single percentile definition)
            List<Double> asDoubles = operationDurations.stream().map(Long::doubleValue).toList();
            p50Latency = (long) StatisticsCalculator.percentile(asDoubles, 50);
            p95Latency = (long) StatisticsCalculator.percentile(asDoubles, 95);
            p99Latency = (long) StatisticsCalculator.percentile(asDoubles, 99);
            maxLatency = operationDurations.getLast();

            double mean = StatisticsCalculator.calculateMean(asDoubles);
            standardDeviation = StatisticsCalculator.calculateStandardDeviation(asDoubles);
            variance = standardDeviation * standardDeviation;

            // Calculate coefficient of variation
            coefficientOfVariation = mean > 0 ? (standardDeviation / mean * 100) : 0;

            // Calculate average CV from periodic snapshots
            if (!statisticsSnapshots.isEmpty()) {
                averageCV = statisticsSnapshots.stream()
                        .mapToDouble(s -> s.coefficientOfVariation)
                        .average()
                        .orElse(0);
            }
        }
    }

    /**
     * Snapshot of statistics from a periodic event.
     */
    static class StatisticsSnapshot {
        long sampleCount;
        long p50Latency;
        long p95Latency;
        long p99Latency;
        double variance;
        double coefficientOfVariation;
        int concurrentThreads;
    }

    /**
     * Main method for command-line usage.
     */
    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            LOGGER.error(JFR_VARIANCE_USAGE);
            System.exit(1);
        }

        Path jfrFile = Path.of(args[0]);
        JfrVarianceAnalyzer analyzer = new JfrVarianceAnalyzer();
        VarianceReport report = analyzer.analyze(jfrFile);
        report.printSummary();
    }
}