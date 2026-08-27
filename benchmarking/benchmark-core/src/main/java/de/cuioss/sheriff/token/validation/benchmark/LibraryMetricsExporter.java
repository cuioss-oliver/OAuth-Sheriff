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

import de.cuioss.benchmarking.common.metrics.MetricsJsonExporter;
import de.cuioss.sheriff.token.validation.metrics.MeasurementType;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.tools.concurrent.StripedRingBufferStatistics;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN;

/**
 * Metrics exporter for library benchmarks that exports StripedRingBufferStatistics
 * from TokenValidatorMonitor. This handles JVM-level performance metrics.
 *
 */
public class LibraryMetricsExporter {

    private static final CuiLogger LOGGER = new CuiLogger(LibraryMetricsExporter.class);
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private static final String DEFAULT_OUTPUT_DIR = "target/benchmark-results";
    private static final String METRICS_FILE = "jwt-validation-metrics.json";

    private static LibraryMetricsExporter instance;
    private final MetricsJsonExporter jsonExporter;

    /**
     * Private constructor for singleton pattern.
     *
     * @param outputDirectory The output directory for metrics files
     */
    private LibraryMetricsExporter(String outputDirectory) {
        Path targetPath = Path.of(outputDirectory);
        this.jsonExporter = new MetricsJsonExporter(targetPath);
    }

    /**
     * Get the singleton instance of LibraryMetricsExporter.
     *
     * @return The singleton instance
     */
    public static synchronized LibraryMetricsExporter getInstance() {
        if (instance == null) {
            instance = new LibraryMetricsExporter(DEFAULT_OUTPUT_DIR);
        }
        return instance;
    }


    public void exportMetrics(String benchmarkMethodName, Instant timestamp, Object metricsData) throws IOException {
        if (!(metricsData instanceof TokenValidatorMonitor monitor)) {
            LOGGER.warn(WARN.INVALID_METRICS_TYPE, metricsData.getClass().getName());
            return;
        }

        // Create metrics for current benchmark
        Map<String, Object> benchmarkMetrics = new LinkedHashMap<>();
        benchmarkMetrics.put("timestamp", ISO_FORMATTER.format(timestamp.atOffset(ZoneOffset.UTC)));

        Map<String, Map<String, Object>> steps = new LinkedHashMap<>();

        // Export metrics for each measurement type
        for (MeasurementType type : monitor.getEnabledTypes()) {
            Optional<StripedRingBufferStatistics> statsOpt = monitor.getValidationMetrics(type);

            if (statsOpt.isPresent()) {
                StripedRingBufferStatistics stats = statsOpt.get();
                if (stats.sampleCount() > 0) {
                    Map<String, Object> stepMetrics = new LinkedHashMap<>();
                    stepMetrics.put("sample_count", stats.sampleCount());

                    // Convert Duration to microseconds and round appropriately
                    stepMetrics.put("p50_us", durationToRoundedMicros(stats.p50()));
                    stepMetrics.put("p95_us", durationToRoundedMicros(stats.p95()));
                    stepMetrics.put("p99_us", durationToRoundedMicros(stats.p99()));

                    steps.put(type.name().toLowerCase(), stepMetrics);
                }
            }
        }

        benchmarkMetrics.put("steps", steps);

        // Update aggregated metrics file using the new concrete class
        jsonExporter.updateAggregatedMetrics(METRICS_FILE, benchmarkMethodName, benchmarkMetrics);
    }

    /**
     * Exports metrics from the provided monitor.
     *
     * @param benchmarkName the name identifying the benchmark that produced these metrics
     * @param monitor       the monitor containing the metrics
     * @throws IOException if writing fails
     */
    public static synchronized void exportMetrics(String benchmarkName, TokenValidatorMonitor monitor) throws IOException {
        getInstance().exportMetrics(benchmarkName, Instant.now(), monitor);
    }

    /**
     * Convert Duration to microseconds with appropriate rounding.
     *
     * @param duration The duration to convert
     * @return Object (Long for values >= 10, Double for values < 10)
     */
    private Object durationToRoundedMicros(Duration duration) {
        double micros = duration.toNanos() / 1000.0;
        return formatNumber(micros);
    }

    /**
     * Format number with appropriate precision for JSON export.
     *
     * @param value The value to format
     * @return Formatted number (Long for values >= 10, Double for values < 10)
     */
    private Object formatNumber(double value) {
        if (value < 10) {
            return Math.round(value * 10.0) / 10.0;
        } else {
            return Math.round(value);
        }
    }
}