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
package de.cuioss.benchmarking.common.jfr;

import jdk.jfr.*;

/**
 * Periodic JFR event that captures operation statistics over time windows.
 * This event is emitted periodically to track variance and performance trends.
 */
@Name("de.cuioss.benchmark.OperationStatistics")
@Label("Operation Statistics")
@Description("Periodic statistics for benchmark operations including latency percentiles and variance metrics")
@Category({"Benchmark", "Performance", "Statistics"})
@Period("1 s")
@StackTrace(false)
public class OperationStatisticsEvent extends Event {

    @Label("Benchmark Name")
    @Description("Name of the benchmark")
    public String benchmarkName;

    @Label("Operation Type")
    @Description("Type of operation")
    public String operationType;

    @Label("Sample Count")
    @Description("Number of operations in this time window")
    public long sampleCount;

    @Label("Success Count")
    @Description("Number of successful operations")
    public long successCount;

    @Label("Error Count")
    @Description("Number of failed operations")
    public long errorCount;

    @Label("Mean Latency")
    @Description("Mean operation latency")
    @Timespan
    public long meanLatency;

    @Label("P50 Latency")
    @Description("50th percentile (median) latency")
    @Timespan
    public long p50Latency;

    @Label("P95 Latency")
    @Description("95th percentile latency")
    @Timespan
    public long p95Latency;

    @Label("P99 Latency")
    @Description("99th percentile latency")
    @Timespan
    public long p99Latency;

    @Label("Max Latency")
    @Description("Maximum observed latency")
    @Timespan
    public long maxLatency;

    @Label("Standard Deviation")
    @Description("Standard deviation of latencies")
    @Timespan
    public long standardDeviation;

    @Label("Variance")
    @Description("Variance of latencies in nanoseconds squared")
    public double variance;

    @Label("Coefficient of Variation")
    @Description("Coefficient of variation (CV) as a percentage")
    public double coefficientOfVariation;

    @Label("Concurrent Threads")
    @Description("Number of concurrent threads during this period")
    public int concurrentThreads;

}