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

import de.cuioss.benchmarking.common.report.StatisticsCalculator;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Transforms Prometheus time-series data into the benchmark server metrics format
 * as defined in benchmark-metrics.adoc.
 * <p>
 * Each metric may be backed by multiple series (e.g. {@code jvm_memory_used_bytes}
 * with different {@code area} labels); the transformer selects or aggregates the
 * relevant series per metric.
 *
 */
public class BenchmarkMetricsTransformer {

    private static final String METRIC_PROCESS_CPU_USAGE = "process_cpu_usage";
    private static final String METRIC_JVM_MEMORY_USED_BYTES = "jvm_memory_used_bytes";

    /**
     * Transforms Prometheus time-series data into benchmark server metrics.
     *
     * @param benchmarkName Name of the benchmark
     * @param startTime Start time of the benchmark
     * @param endTime End time of the benchmark
     * @param timeSeriesData Raw time-series data from Prometheus (all series per metric)
     * @return Structured benchmark metrics as defined in requirements
     */
    public Map<String, Object> transformToServerMetrics(
            String benchmarkName,
            Instant startTime,
            Instant endTime,
            Map<String, List<PrometheusClient.TimeSeries>> timeSeriesData) {

        Map<String, Object> result = new LinkedHashMap<>();
        Duration duration = Duration.between(startTime, endTime);

        // Benchmark metadata
        Map<String, Object> benchmark = new LinkedHashMap<>();
        benchmark.put("name", benchmarkName);
        benchmark.put("start_time", startTime.toString());
        benchmark.put("end_time", endTime.toString());
        benchmark.put("duration_seconds", duration.getSeconds());
        result.put("benchmark", benchmark);

        // Resource metrics
        result.put("resources", createResourceMetrics(timeSeriesData));

        // Application metrics
        result.put("application", createApplicationMetrics(timeSeriesData));

        return result;
    }


    private Map<String, Object> createResourceMetrics(Map<String, List<PrometheusClient.TimeSeries>> data) {
        Map<String, Object> resources = new LinkedHashMap<>();

        // CPU metrics
        Map<String, Object> cpu = new LinkedHashMap<>();
        cpu.put("process", createCpuMetrics(firstSeries(data, METRIC_PROCESS_CPU_USAGE), "Process"));
        cpu.put("system", createCpuMetrics(firstSeries(data, "system_cpu_usage"), "System"));

        // Get CPU cores
        PrometheusClient.TimeSeries cpuCount = firstSeries(data, "system_cpu_count");
        if (cpuCount != null && !cpuCount.values().isEmpty()) {
            cpu.put("cores_available", (int) cpuCount.values().getFirst().value());
        } else {
            cpu.put("cores_available", 4); // Default
        }
        resources.put("cpu", cpu);

        // Memory metrics
        resources.put("memory", createMemoryMetrics(data));

        // Thread metrics
        resources.put("threads", createThreadMetrics(data));

        return resources;
    }

    private Map<String, Object> createCpuMetrics(PrometheusClient.TimeSeries series, String type) {
        Map<String, Object> cpuMetrics = new LinkedHashMap<>();

        if (series == null || series.values().isEmpty()) {
            cpuMetrics.put("average_percent", 0.0);
            cpuMetrics.put("peak_percent", 0.0);
            cpuMetrics.put("std_dev", 0.0);
            return cpuMetrics;
        }

        List<Double> values = series.values().stream()
                .map(dp -> dp.value() * 100) // Convert to percentage
                .toList();

        Statistics stats = calculateStatistics(values);

        cpuMetrics.put("average_percent", round(stats.mean, 1));
        cpuMetrics.put("peak_percent", round(stats.max, 1));
        cpuMetrics.put("std_dev", round(stats.stdDev, 2));

        if ("Process".equals(type)) {
            Map<String, Object> percentiles = new LinkedHashMap<>();
            percentiles.put("p50", round(stats.p50, 1));
            percentiles.put("p75", round(stats.p75, 1));
            percentiles.put("p90", round(stats.p90, 1));
            percentiles.put("p99", round(stats.p99, 1));
            cpuMetrics.put("percentiles", percentiles);
        }

        return cpuMetrics;
    }

    private Map<String, Object> createMemoryMetrics(Map<String, List<PrometheusClient.TimeSeries>> data) {
        Map<String, Object> memory = new LinkedHashMap<>();

        // Heap memory - select the series labeled area="heap" from all memory series
        Map<String, Object> heap = new LinkedHashMap<>();
        PrometheusClient.TimeSeries heapUsed = findHeapMemory(data.get(METRIC_JVM_MEMORY_USED_BYTES));
        if (heapUsed != null && !heapUsed.values().isEmpty()) {
            List<Double> heapMbValues = heapUsed.values().stream()
                    .map(dp -> dp.value() / 1024 / 1024) // Convert to MB
                    .toList();

            Statistics stats = calculateStatistics(heapMbValues);
            heap.put("average_mb", round(stats.mean, 1));
            heap.put("peak_mb", round(stats.max, 1));
            heap.put("final_mb", round(heapMbValues.getLast(), 1));
        } else {
            heap.put("average_mb", 0.0);
            heap.put("peak_mb", 0.0);
            heap.put("final_mb", 0.0);
        }
        memory.put("heap", heap);

        // GC metrics
        Map<String, Object> gc = new LinkedHashMap<>();
        PrometheusClient.TimeSeries gcOverhead = firstSeries(data, "jvm_gc_overhead");
        if (gcOverhead != null && !gcOverhead.values().isEmpty()) {
            double avgOverhead = gcOverhead.values().stream()
                    .mapToDouble(PrometheusClient.DataPoint::value)
                    .average().orElse(0.0);
            gc.put("overhead_percent", round(avgOverhead * 100, 2));
        } else {
            gc.put("overhead_percent", 0.0);
        }
        memory.put("gc", gc);

        return memory;
    }

    private Map<String, Object> createThreadMetrics(Map<String, List<PrometheusClient.TimeSeries>> data) {
        Map<String, Object> threads = new LinkedHashMap<>();

        PrometheusClient.TimeSeries liveThreads = firstSeries(data, "jvm_threads_live_threads");
        if (liveThreads != null && !liveThreads.values().isEmpty()) {
            Statistics stats = calculateStatistics(
                    liveThreads.values().stream()
                            .map(PrometheusClient.DataPoint::value)
                            .toList()
            );
            threads.put("average", (int) stats.mean);
            threads.put("peak", (int) stats.max);
            threads.put("final", (int) liveThreads.values().getLast().value());
        } else {
            threads.put("average", 0);
            threads.put("peak", 0);
            threads.put("final", 0);
        }

        PrometheusClient.TimeSeries daemonThreads = firstSeries(data, "jvm_threads_daemon_threads");
        if (daemonThreads != null && !daemonThreads.values().isEmpty()) {
            threads.put("daemon", (int) daemonThreads.values().getFirst().value());
        } else {
            threads.put("daemon", 0);
        }

        return threads;
    }


    private Map<String, Object> createApplicationMetrics(Map<String, List<PrometheusClient.TimeSeries>> data) {
        Map<String, Object> application = new LinkedHashMap<>();

        Map<String, Object> jwtValidations = new LinkedHashMap<>();

        // JWT validation metrics - aggregate across ALL series (e.g. per event_type label)
        double totalSuccess = 0;
        double cacheHits = 0;

        for (PrometheusClient.TimeSeries series : allSeries(data, "sheriff_token_validation_success_operations_total")) {
            double delta = getDeltaValue(series);
            totalSuccess += delta;
            // Check if it's a cache hit based on metric labels
            if (series.labels().containsKey("event_type") &&
                    series.labels().get("event_type").contains("CACHE_HIT")) {
                cacheHits += delta;
            }
        }

        double totalErrors = 0;
        for (PrometheusClient.TimeSeries series : allSeries(data, "sheriff_token_validation_errors_total")) {
            totalErrors += getDeltaValue(series);
        }

        double total = totalSuccess + totalErrors;
        jwtValidations.put("total", (int) total);
        jwtValidations.put("success", (int) totalSuccess);
        jwtValidations.put("errors", (int) totalErrors);
        jwtValidations.put("cache_hits", (int) cacheHits);
        jwtValidations.put("cache_hit_rate_percent", total > 0 ? round(cacheHits / total * 100, 1) : 0.0);

        // JWT validation timing - aggregate sums/counts across all series
        double sum = 0;
        double count = 0;
        for (PrometheusClient.TimeSeries series : allSeries(data, "sheriff_token_bearer_token_validation_seconds_sum")) {
            sum += getDeltaValue(series);
        }
        for (PrometheusClient.TimeSeries series : allSeries(data, "sheriff_token_bearer_token_validation_seconds_count")) {
            count += getDeltaValue(series);
        }
        if (count > 0) {
            jwtValidations.put("average_validation_time_ms", round(sum / count * 1000, 2));
        }

        application.put("jwt_validations", jwtValidations);

        return application;
    }

    /**
     * Returns the first series of a metric, or {@code null} if the metric has no series.
     * Use for metrics that are expected to have exactly one series.
     */
    private PrometheusClient.TimeSeries firstSeries(Map<String, List<PrometheusClient.TimeSeries>> data, String metricName) {
        List<PrometheusClient.TimeSeries> series = data.get(metricName);
        return series == null || series.isEmpty() ? null : series.getFirst();
    }

    /**
     * Returns all series of a metric, or an empty list if the metric has no series.
     */
    private List<PrometheusClient.TimeSeries> allSeries(Map<String, List<PrometheusClient.TimeSeries>> data, String metricName) {
        List<PrometheusClient.TimeSeries> series = data.get(metricName);
        return series == null ? List.of() : series;
    }

    /**
     * Selects the heap memory series (label {@code area="heap"}) from all memory series.
     *
     * @param memorySeries all series of the memory metric, may be {@code null}
     * @return the heap series, or {@code null} if none is labeled as heap
     */
    private PrometheusClient.TimeSeries findHeapMemory(List<PrometheusClient.TimeSeries> memorySeries) {
        if (memorySeries == null) {
            return null;
        }
        return memorySeries.stream()
                .filter(series -> "heap".equals(series.labels().get("area")))
                .findFirst()
                .orElse(null);
    }

    private double getDeltaValue(PrometheusClient.TimeSeries series) {
        if (series == null || series.values().isEmpty()) {
            return 0;
        }
        List<PrometheusClient.DataPoint> values = series.values();
        if (values.size() == 1) {
            return values.getFirst().value();
        }
        // For counters, get the difference between last and first
        return values.getLast().value() - values.getFirst().value();
    }

    private Statistics calculateStatistics(List<Double> values) {
        if (values.isEmpty()) {
            return new Statistics();
        }

        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);

        Statistics stats = new Statistics();
        stats.mean = StatisticsCalculator.calculateMean(values);
        stats.min = sorted.getFirst();
        stats.max = sorted.getLast();
        stats.stdDev = StatisticsCalculator.calculateStandardDeviation(values);

        stats.p50 = StatisticsCalculator.percentile(sorted, 50);
        stats.p75 = StatisticsCalculator.percentile(sorted, 75);
        stats.p90 = StatisticsCalculator.percentile(sorted, 90);
        stats.p99 = StatisticsCalculator.percentile(sorted, 99);

        return stats;
    }

    private double round(double value, int decimals) {
        double scale = Math.pow(10, decimals);
        return Math.round(value * scale) / scale;
    }

    private static class Statistics {
        double mean = 0;
        double min = 0;
        double max = 0;
        double stdDev = 0;
        double p50 = 0;
        double p75 = 0;
        double p90 = 0;
        double p99 = 0;
    }
}
