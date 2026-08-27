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
package de.cuioss.benchmarking.common.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.options.TimeValue;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class BenchmarkConfigurationTest {

    @TempDir
    Path tempDir;

    private void setRequiredSystemProperties() {
        System.setProperty("jmh.include", ".*Benchmark.*");
        System.setProperty("jmh.forks", "1");
        System.setProperty("jmh.warmupIterations", "3");
        System.setProperty("jmh.iterations", "5");
        System.setProperty("jmh.time", "2s");
        System.setProperty("jmh.warmupTime", "1s");
        System.setProperty("jmh.threads", "4");
    }

    private void clearSystemProperties() {
        System.clearProperty("jmh.include");
        System.clearProperty("jmh.forks");
        System.clearProperty("jmh.warmupIterations");
        System.clearProperty("jmh.iterations");
        System.clearProperty("jmh.time");
        System.clearProperty("jmh.warmupTime");
        System.clearProperty("jmh.threads");
        System.clearProperty("jmh.result.format");
    }

    @Test
    void builderWithSystemProperties() {
        // Set all required system properties
        System.setProperty("jmh.include", ".*SystemTest.*");
        System.setProperty("jmh.result.format", "TEXT");
        System.setProperty("jmh.forks", "3");
        System.setProperty("jmh.warmupIterations", "5");
        System.setProperty("jmh.iterations", "10");
        System.setProperty("jmh.time", "3s");
        System.setProperty("jmh.warmupTime", "2s");
        System.setProperty("jmh.threads", "16");

        BenchmarkConfiguration config = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("sysThroughput")
                .withLatencyBenchmarkName("sysLatency")
                .build();

        assertEquals(".*SystemTest.*", config.includePattern());
        assertEquals(ResultFormatType.TEXT, config.reportConfig().resultFormat());
        assertEquals(3, config.forks());
        assertEquals(16, config.threads());

        // Clean up system properties
        clearSystemProperties();
    }

    @Test
    void toJmhOptions() {
        BenchmarkConfiguration config = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("jmhThroughput")
                .withLatencyBenchmarkName("jmhLatency")
                .withIncludePattern(".*JmhTest.*")
                .withResultFormat(ResultFormatType.JSON)
                .withForks(2)
                .withThreads(8)
                .withWarmupIterations(10)
                .withMeasurementIterations(20)
                .withMeasurementTime(TimeValue.seconds(3))
                .withWarmupTime(TimeValue.seconds(2))
                .withResultsDirectory(tempDir.resolve("benchmark-results").toString())
                .build();

        // Verify the configuration values are properly set
        assertEquals(".*JmhTest.*", config.includePattern(), "Include pattern should match");
        assertEquals(2, config.forks(), "Forks should be 2");
        assertEquals(8, config.threads(), "Threads should be 8");
        assertEquals(10, config.warmupIterations(), "Warmup iterations should be 10");
        assertEquals(20, config.measurementIterations(), "Measurement iterations should be 20");
        assertEquals(tempDir.resolve("benchmark-results").toString(), config.resultsDirectory(), "Results directory should match");
        assertEquals(ResultFormatType.JSON, config.reportConfig().resultFormat(), "Result format should be JSON");
    }

    @Test
    void threadCountParsing() {
        setRequiredSystemProperties();
        System.setProperty("jmh.threads", "MAX");
        BenchmarkConfiguration config = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("threadThroughput")
                .withLatencyBenchmarkName("threadLatency")
                .build();
        assertEquals(Runtime.getRuntime().availableProcessors(), config.threads());
        clearSystemProperties();

        setRequiredSystemProperties();
        System.setProperty("jmh.threads", "HALF");
        BenchmarkConfiguration config2 = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("threadThroughput")
                .withLatencyBenchmarkName("threadLatency")
                .build();
        assertEquals(Math.max(1, Runtime.getRuntime().availableProcessors() / 2), config2.threads());
        clearSystemProperties();
    }

    @Test
    void timeValueParsing() {
        setRequiredSystemProperties();
        System.setProperty("jmh.time", "5s");
        System.setProperty("jmh.warmupTime", "2m");
        BenchmarkConfiguration config = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("timeThroughput")
                .withLatencyBenchmarkName("timeLatency")
                .build();
        assertEquals(TimeValue.seconds(5), config.measurementTime());
        assertEquals(TimeValue.minutes(2), config.warmupTime());
        clearSystemProperties();
    }

    @Test
    void resultFileGeneration() {
        setRequiredSystemProperties();
        BenchmarkConfiguration config = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.INTEGRATION)
                .withThroughputBenchmarkName("fileThroughput")
                .withLatencyBenchmarkName("fileLatency")
                .withResultsDirectory(tempDir.resolve("test-results").toString())
                .withResultFile(tempDir.resolve("test-results").resolve("custom-result.json").toString())
                .build();

        // Verify configuration values are accessible
        assertEquals(tempDir.resolve("test-results").toString(), config.resultsDirectory());
        assertEquals(tempDir.resolve("test-results").resolve("custom-result.json").toString(), config.resultFile());
        assertEquals(BenchmarkType.INTEGRATION, config.benchmarkType());
        assertEquals("fileThroughput", config.throughputBenchmarkName());
        assertEquals("fileLatency", config.latencyBenchmarkName());

        // Verify configuration is created successfully
        assertNotNull(config, "Configuration should not be null");

        // Test that result file can be generated when not explicitly set
        BenchmarkConfiguration configWithoutFile = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.INTEGRATION)
                .withThroughputBenchmarkName("throughput")
                .withLatencyBenchmarkName("latency")
                .withResultsDirectory(tempDir.resolve("generated-results").toString())
                .build();

        assertNull(configWithoutFile.resultFile(), "Result file should be null when not set");
        assertEquals(tempDir.resolve("generated-results").toString(), configWithoutFile.resultsDirectory());

        // The actual result file will be generated when needed by the runner
        assertNotNull(configWithoutFile.reportConfig(), "Report config should exist");
        clearSystemProperties();
    }

    @Test
    void invalidResultFormat() {
        setRequiredSystemProperties();
        System.setProperty("jmh.result.format", "INVALID");
        BenchmarkConfiguration config = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("formatThroughput")
                .withLatencyBenchmarkName("formatLatency")
                .build();
        assertEquals(ResultFormatType.JSON, config.reportConfig().resultFormat()); // Should default to JSON
        System.clearProperty("jmh.result.format");
        clearSystemProperties();
    }

    @Test
    void timeValueParsingEdgeCases() {
        setRequiredSystemProperties();
        System.setProperty("jmh.time", "1h");
        BenchmarkConfiguration config = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("edgeThroughput")
                .withLatencyBenchmarkName("edgeLatency")
                .build();
        assertEquals(TimeValue.hours(1), config.measurementTime());
        clearSystemProperties();

        // Test invalid time unit (should warn and use number as seconds)
        setRequiredSystemProperties();
        System.setProperty("jmh.warmupTime", "10x");
        BenchmarkConfiguration config2 = BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("edgeThroughput")
                .withLatencyBenchmarkName("edgeLatency")
                .build();
        assertEquals(TimeValue.seconds(10), config2.warmupTime());
        clearSystemProperties();

        // Note: Testing empty time value would fail with requireProperty,
        // so that case is removed. Empty values are not allowed anymore
    }

    @Test
    void recordEquality() {
        BenchmarkConfiguration config1 = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("eqThroughput")
                .withLatencyBenchmarkName("eqLatency")
                .withIncludePattern(".*Test.*")
                .withForks(2)
                .build();

        BenchmarkConfiguration config2 = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("eqThroughput")
                .withLatencyBenchmarkName("eqLatency")
                .withIncludePattern(".*Test.*")
                .withForks(2)
                .build();

        BenchmarkConfiguration config3 = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("eqThroughput")
                .withLatencyBenchmarkName("eqLatency")
                .withIncludePattern(".*Different.*")
                .withForks(2)
                .build();

        assertEquals(config1, config2);
        assertNotEquals(config1, config3);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    void requiredFieldValidation() {
        // Missing benchmark type
        var builder1 = new BenchmarkConfiguration.Builder()
                .withThroughputBenchmarkName("throughput")
                .withLatencyBenchmarkName("latency");
        assertThrows(IllegalArgumentException.class, builder1::build);

        // Missing throughput benchmark name
        var builder2 = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withLatencyBenchmarkName("latency");
        assertThrows(IllegalArgumentException.class, builder2::build);

        // Missing latency benchmark name
        var builder3 = new BenchmarkConfiguration.Builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("throughput");
        assertThrows(IllegalArgumentException.class, builder3::build);
    }
}