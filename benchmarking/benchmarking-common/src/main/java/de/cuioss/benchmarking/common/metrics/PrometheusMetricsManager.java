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

import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.ERROR.FAILED_COLLECT_PROMETHEUS_BENCHMARK;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.ERROR.PROMETHEUS_CONNECTIVITY_FAILED;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO.*;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN.MISSING_TIMESTAMPS_FOR_COLLECTION;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN.SKIPPING_PROMETHEUS_COLLECTION;

/**
 * Centralized manager for Prometheus metrics collection during benchmark execution.
 * Collects real-time metrics from Prometheus for WRK benchmarks.
 *
 * <p>Features:</p>
 * <ul>
 *   <li>Automatic Prometheus client configuration from system properties</li>
 *   <li>Integration with MetricsOrchestrator for actual metrics retrieval</li>
 * </ul>
 */
public class PrometheusMetricsManager {

    private static final CuiLogger LOGGER = new CuiLogger(PrometheusMetricsManager.class);

    public static final String PROMETHEUS_DIR_NAME = "prometheus";
    public static final String PROMETHEUS_URL_PROPERTY = "prometheus.url";
    public static final String PROMETHEUS_URL_DEFAULT = "http://localhost:9090";
    public static final String METRICS_FILE_SUFFIX = "-metrics.json";

    private final String prometheusUrl;
    private final boolean metricsEnabled;

    /**
     * Creates a new PrometheusMetricsManager.
     * Prometheus URL is read from system property or defaults to localhost:9090.
     */
    public PrometheusMetricsManager() {
        this.prometheusUrl = System.getProperty(PROMETHEUS_URL_PROPERTY, PROMETHEUS_URL_DEFAULT);
        this.metricsEnabled = isPrometheusAvailable();

        if (metricsEnabled) {
            LOGGER.info(PROMETHEUS_ENABLED, prometheusUrl);
        } else {
            LOGGER.info(PROMETHEUS_DISABLED, prometheusUrl);
        }
    }

    /**
     * Collects Prometheus metrics for WRK benchmark results.
     * This method handles the specific case of WRK benchmarks where
     * timestamps are extracted from the output files.
     *
     * @param benchmarkName the name of the benchmark
     * @param startTime the benchmark start time
     * @param endTime the benchmark end time
     * @param outputDirectory the directory to save metrics
     */
    public void collectMetricsForWrkBenchmark(String benchmarkName, Instant startTime,
            Instant endTime, String outputDirectory) {
        if (!metricsEnabled) {
            LOGGER.warn(SKIPPING_PROMETHEUS_COLLECTION, prometheusUrl);
            LOGGER.debug("To enable metrics collection, ensure Prometheus is running and accessible at the configured URL");
            return;
        }

        if (startTime == null || endTime == null) {
            LOGGER.warn(MISSING_TIMESTAMPS_FOR_COLLECTION, benchmarkName);
            return;
        }

        try {
            Path prometheusDir = Path.of(outputDirectory, PROMETHEUS_DIR_NAME);
            Files.createDirectories(prometheusDir);

            LOGGER.info(COLLECTING_WRK_PROMETHEUS_METRICS, benchmarkName);

            MetricsOrchestrator orchestrator = new MetricsOrchestrator(
                    new PrometheusClient(prometheusUrl)
            );

            orchestrator.collectBenchmarkMetrics(
                    benchmarkName,
                    startTime,
                    endTime,
                    prometheusDir
            );

            LOGGER.info(PROMETHEUS_METRICS_SAVED, prometheusDir, benchmarkName, METRICS_FILE_SUFFIX);

        } catch (IOException e) {
            LOGGER.error(e, FAILED_COLLECT_PROMETHEUS_BENCHMARK, benchmarkName, prometheusUrl);
            LOGGER.debug("Attempted to query metrics for time range: %s to %s", startTime, endTime);
        }
    }

    private boolean isPrometheusAvailable() {
        try {
            LOGGER.debug("Checking Prometheus availability at URL: %s", prometheusUrl);
            PrometheusClient client = new PrometheusClient(prometheusUrl);
            client.queryRange(List.of("up"), Instant.now().minusSeconds(60), Instant.now(), Duration.ofSeconds(10));
            LOGGER.debug("Prometheus is available and responding at: %s", prometheusUrl);
            return true;
        } catch (PrometheusClient.PrometheusException e) {
            LOGGER.error(e, PROMETHEUS_CONNECTIVITY_FAILED, prometheusUrl, e.getMessage(), e.getClass().getSimpleName());
            LOGGER.info(PROMETHEUS_CONNECTIVITY_ADVICE, prometheusUrl);
            return false;
        }
    }

}